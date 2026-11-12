import { unlink } from 'node:fs/promises';
import { ERROR_CODES, WriteGuardError } from './errors.js';
import {
  appendAuditLog,
  atomicWriteJson,
  ensureStateDirs,
  getLocalDayKey,
  readJsonIfExists,
  resolveStatePaths,
} from './storage.js';

export const DEFAULT_KILL_SWITCH_CONFIG = Object.freeze({
  statusCodes: [429, 402],
  errorPatterns: [
    /rate[\s_-]?limit/i,
    /too many requests/i,
    /spend[\s_-]?limit/i,
    /insufficient[\s_-]?funds/i,
    /account[\s_-]?suspended/i,
  ],
});

/**
 * Reads the active STOP kill-switch file if present.
 *
 * @param {string} stateDir
 */
export async function getKillSwitch(stateDir) {
  const paths = resolveStatePaths(stateDir);
  return readJsonIfExists(paths.stopPath);
}

/**
 * Returns true if the STOP kill-switch is currently active.
 *
 * @param {string} stateDir
 */
export async function isStopped(stateDir) {
  const record = await getKillSwitch(stateDir);
  return record !== null;
}

/**
 * Trips the STOP kill-switch immediately, blocking all further mutating writes.
 *
 * @param {string} stateDir
 * @param {{ reason: string, signal?: string, actionKey?: string, metadata?: object, now?: Date }} options
 */
export async function tripKillSwitch(
  stateDir,
  { reason = 'Manual kill-switch activation', signal = 'MANUAL', actionKey = null, metadata = {}, now = new Date() } = {},
) {
  const paths = await ensureStateDirs(stateDir);
  const record = {
    active: true,
    reason: String(reason),
    signal: String(signal),
    actionKey,
    trippedAt: now.toISOString(),
    pid: process.pid,
    metadata,
  };
  await atomicWriteJson(paths.stopPath, record, 0o600);
  await appendAuditLog(stateDir, {
    ts: now.toISOString(),
    event: 'killswitch.tripped',
    reason: record.reason,
    signal: record.signal,
    actionKey,
  });
  return record;
}

/**
 * Clears the STOP kill-switch with explicit operator audit attribution.
 *
 * @param {string} stateDir
 * @param {{ operator?: string, reason?: string, now?: Date }} [options]
 */
export async function clearKillSwitch(
  stateDir,
  { operator = 'operator', reason = 'Cleared after review', now = new Date() } = {},
) {
  const paths = resolveStatePaths(stateDir);
  const existing = await readJsonIfExists(paths.stopPath);
  if (!existing) {
    return { cleared: false, wasActive: false };
  }
  await unlink(paths.stopPath).catch((err) => {
    if (err?.code !== 'ENOENT') throw err;
  });
  await appendAuditLog(stateDir, {
    ts: now.toISOString(),
    event: 'killswitch.cleared',
    operator: String(operator),
    reason: String(reason),
    previousSignal: existing.signal,
    previousReason: existing.reason,
  });
  return { cleared: true, wasActive: true, previous: existing };
}

/**
 * Inspects an error or response object against kill-switch trigger rules.
 *
 * @param {any} error
 * @param {{ statusCodes?: number[], errorPatterns?: Array<string | RegExp> }} [config]
 * @returns {{ shouldTrip: boolean, signal?: string, reason?: string }}
 */
export function shouldTripOnError(error, config = DEFAULT_KILL_SWITCH_CONFIG) {
  if (!error) return { shouldTrip: false };
  const statusCodes = config?.statusCodes ?? DEFAULT_KILL_SWITCH_CONFIG.statusCodes;
  const rawPatterns = config?.errorPatterns ?? DEFAULT_KILL_SWITCH_CONFIG.errorPatterns;

  const status = Number(
    error.status ??
    error.statusCode ??
    error.response?.status ??
    error.response?.statusCode ??
    NaN,
  );
  if (Number.isFinite(status) && statusCodes.includes(status)) {
    return {
      shouldTrip: true,
      signal: `HTTP_${status}`,
      reason: `Auto-tripped kill switch on HTTP ${status}: ${error.message || 'upstream block signal'}`,
    };
  }

  const haystack = [
    typeof error === 'string' ? error : '',
    error?.message || '',
    error?.stderr || '',
    error?.stdout || '',
    error?.code || '',
  ]
    .filter(Boolean)
    .join('\n');

  for (const pat of rawPatterns) {
    const re = pat instanceof RegExp ? pat : new RegExp(String(pat), 'i');
    if (re.test(haystack)) {
      return {
        shouldTrip: true,
        signal: `PATTERN:${re.source}`,
        reason: `Auto-tripped kill switch on error pattern ${re.toString()}`,
      };
    }
  }

  return { shouldTrip: false };
}

async function loadLedgerForDay(stateDir, dayKey) {
  const paths = resolveStatePaths(stateDir);
  const existing = await readJsonIfExists(paths.capsPath);
  if (!existing || existing.dayKey !== dayKey) {
    return {
      dayKey,
      counts: {},
      totalSpend: 0,
      rolledOverFrom: existing?.dayKey || null,
      updatedAt: null,
    };
  }
  return {
    dayKey: existing.dayKey,
    counts: { ...(existing.counts || {}) },
    totalSpend: Number(existing.totalSpend || 0),
    rolledOverFrom: existing.rolledOverFrom || null,
    updatedAt: existing.updatedAt || null,
  };
}

function resolveLimitForAction(caps = {}, action) {
  if (Object.prototype.hasOwnProperty.call(caps, action)) {
    return caps[action];
  }
  if (Object.prototype.hasOwnProperty.call(caps, '*')) {
    return caps['*'];
  }
  return null;
}

/**
 * Checks whether an action (and optional spend amount) is within today's local-day cap.
 * Automatically rolls over counters when the local date advances.
 *
 * @param {string} stateDir
 * @param {{ action: string, amount?: number, caps?: Record<string, number>, maxDailySpend?: number, now?: Date, timeZone?: string }} options
 */
export async function checkCap(
  stateDir,
  { action, amount = 0, caps = {}, maxDailySpend, now = new Date(), timeZone } = {},
) {
  const dayKey = getLocalDayKey(now, timeZone);
  const ledger = await loadLedgerForDay(stateDir, dayKey);
  const used = Number(ledger.counts[action] || 0);
  const limit = resolveLimitForAction(caps, action);
  const spendAmount = Number(amount || 0);

  if (limit !== null && limit !== undefined && used + 1 > limit) {
    return {
      allowed: false,
      code: ERROR_CODES.ERR_DAILY_CAP_EXCEEDED,
      dayKey,
      action,
      used,
      limit,
      remaining: Math.max(0, limit - used),
      totalSpend: ledger.totalSpend,
      maxDailySpend: maxDailySpend ?? null,
      reason: `Daily cap exceeded for "${action}": ${used}/${limit} used on ${dayKey}.`,
    };
  }

  if (
    typeof maxDailySpend === 'number' &&
    Number.isFinite(maxDailySpend) &&
    spendAmount > 0 &&
    ledger.totalSpend + spendAmount > maxDailySpend
  ) {
    return {
      allowed: false,
      code: ERROR_CODES.ERR_SPEND_CEILING_EXCEEDED,
      dayKey,
      action,
      used,
      limit,
      remaining: limit !== null && limit !== undefined ? Math.max(0, limit - used) : null,
      totalSpend: ledger.totalSpend,
      projectedSpend: ledger.totalSpend + spendAmount,
      maxDailySpend,
      reason: `Daily spend ceiling exceeded on ${dayKey}: projected ${ledger.totalSpend + spendAmount} > limit ${maxDailySpend}.`,
    };
  }

  return {
    allowed: true,
    dayKey,
    action,
    used,
    limit,
    remaining: limit !== null && limit !== undefined ? Math.max(0, limit - used) : null,
    totalSpend: ledger.totalSpend,
    maxDailySpend: maxDailySpend ?? null,
  };
}

/**
 * Checks and records one unit of daily cap usage (plus optional spend) atomically.
 *
 * @param {string} stateDir
 * @param {{ action: string, amount?: number, caps?: Record<string, number>, maxDailySpend?: number, tripOnSpendCeiling?: boolean, now?: Date, timeZone?: string }} options
 */
export async function consumeCap(
  stateDir,
  { action, amount = 0, caps = {}, maxDailySpend, tripOnSpendCeiling = false, now = new Date(), timeZone } = {},
) {
  const paths = await ensureStateDirs(stateDir);
  const status = await checkCap(stateDir, { action, amount, caps, maxDailySpend, now, timeZone });
  if (!status.allowed) {
    if (status.code === ERROR_CODES.ERR_SPEND_CEILING_EXCEEDED && tripOnSpendCeiling) {
      await tripKillSwitch(stateDir, {
        reason: status.reason,
        signal: 'SPEND_CEILING',
        now,
      });
    }
    throw new WriteGuardError(status.code, status.reason, { details: status });
  }

  const dayKey = status.dayKey;
  const ledger = await loadLedgerForDay(stateDir, dayKey);
  const spendAmount = Number(amount || 0);
  ledger.counts[action] = Number(ledger.counts[action] || 0) + 1;
  ledger.totalSpend = Number((ledger.totalSpend + spendAmount).toFixed(6));
  ledger.updatedAt = now.toISOString();

  await atomicWriteJson(paths.capsPath, ledger, 0o600);
  return {
    dayKey,
    action,
    used: ledger.counts[action],
    limit: status.limit,
    remaining: status.limit !== null && status.limit !== undefined ? Math.max(0, status.limit - ledger.counts[action]) : null,
    totalSpend: ledger.totalSpend,
    maxDailySpend: maxDailySpend ?? null,
  };
}

/**
 * Returns current local-day quota usage across all tracked & configured actions.
 *
 * @param {string} stateDir
 * @param {{ caps?: Record<string, number>, maxDailySpend?: number, now?: Date, timeZone?: string }} [options]
 */
export async function getCapsStatus(stateDir, { caps = {}, maxDailySpend = null, now = new Date(), timeZone } = {}) {
  const dayKey = getLocalDayKey(now, timeZone);
  const ledger = await loadLedgerForDay(stateDir, dayKey);
  const actionNames = new Set([...Object.keys(caps || {}), ...Object.keys(ledger.counts || {})]);
  const actions = {};
  for (const name of [...actionNames].sort()) {
    const used = Number(ledger.counts[name] || 0);
    const limit = resolveLimitForAction(caps, name);
    actions[name] = {
      used,
      limit,
      remaining: limit !== null && limit !== undefined ? Math.max(0, limit - used) : null,
    };
  }
  return {
    dayKey,
    totalSpend: ledger.totalSpend,
    maxDailySpend: maxDailySpend ?? null,
    rolledOverFrom: ledger.rolledOverFrom,
    actions,
  };
}
