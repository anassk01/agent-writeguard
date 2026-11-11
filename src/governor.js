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
