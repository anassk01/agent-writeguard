import { randomBytes } from 'node:crypto';
import {
  appendFile,
  mkdir,
  open,
  readFile,
  rename,
  unlink,
} from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { ERROR_CODES, WriteGuardError } from './errors.js';

export function resolveStatePaths(stateDir) {
  const root = resolve(stateDir || '.writeguard');
  return {
    root,
    configPath: join(root, 'config.json'),
    attestationsDir: join(root, 'attestations'),
    locksDir: join(root, 'locks'),
    archiveDir: join(root, 'locks', 'archive'),
    capsPath: join(root, 'caps.json'),
    identityPath: join(root, 'identity.json'),
    stopPath: join(root, 'STOP'),
    auditPath: join(root, 'audit.jsonl'),
  };
}

export async function ensureStateDirs(stateDir) {
  const paths = resolveStatePaths(stateDir);
  await mkdir(paths.root, { recursive: true, mode: 0o700 });
  await mkdir(paths.attestationsDir, { recursive: true, mode: 0o700 });
  await mkdir(paths.locksDir, { recursive: true, mode: 0o700 });
  await mkdir(paths.archiveDir, { recursive: true, mode: 0o700 });
  return paths;
}

/**
 * Atomically writes JSON to disk via temp file in same directory + rename.
 *
 * @param {string} filePath
 * @param {unknown} data
 * @param {number} [mode]
 */
export async function atomicWriteJson(filePath, data, mode = 0o600) {
  const dir = dirname(filePath);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const tmpPath = join(dir, `.tmp-${process.pid}-${Date.now()}-${randomBytes(6).toString('hex')}`);
  const payload = `${JSON.stringify(data, null, 2)}\n`;
  let handle;
  try {
    handle = await open(tmpPath, 'wx', mode);
    await handle.writeFile(payload, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(tmpPath, filePath);
  } catch (err) {
    if (handle) {
      await handle.close().catch(() => {});
    }
    await unlink(tmpPath).catch(() => {});
    throw err;
  }
}

/**
 * Reads and parses a JSON file, returning null if ENOENT.
 *
 * @param {string} filePath
 * @returns {Promise<any | null>}
 */
export async function readJsonIfExists(filePath) {
  try {
    const raw = await readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      return null;
    }
    throw err;
  }
}

/**
 * Appends a structured JSONL event to `<stateDir>/audit.jsonl`.
 *
 * @param {string} stateDir
 * @param {object} event
 */
export async function appendAuditLog(stateDir, event) {
  const paths = resolveStatePaths(stateDir);
  await mkdir(paths.root, { recursive: true, mode: 0o700 });
  const entry = {
    ts: event.ts || new Date().toISOString(),
    ...event,
  };
  await appendFile(paths.auditPath, `${JSON.stringify(entry)}\n`, { encoding: 'utf8', mode: 0o600 });
}

/**
 * Parses a duration string like '24h', '30m', '60s', '7d', '500ms' or numeric ms.
 *
 * @param {number | string} input
 * @returns {number}
 */
export function parseDurationMs(input) {
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || input <= 0) {
      throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, `Invalid duration: ${input}`);
    }
    return input;
  }
  if (typeof input !== 'string' || input.trim() === '') {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, `Invalid duration: ${String(input)}`);
  }
  const match = input.trim().match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$/i);
  if (!match) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_INVALID_ARGUMENT,
      `Could not parse duration "${input}". Use e.g. 60s, 30m, 24h, 7d, or milliseconds.`,
    );
  }
  const value = Number(match[1]);
  const unit = (match[2] || 'ms').toLowerCase();
  const multipliers = {
    ms: 1,
    s: 1_000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
  };
  const result = Math.round(value * multipliers[unit]);
  if (!Number.isFinite(result) || result <= 0) {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, `Duration must be positive: "${input}"`);
  }
  return result;
}

/**
 * Returns local calendar day key `YYYY-MM-DD` (respecting optional IANA timeZone).
 *
 * @param {Date | number | string} [date]
 * @param {string} [timeZone]
 * @returns {string}
 */
export function getLocalDayKey(date = new Date(), timeZone) {
  const d = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(d.getTime())) {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, `Invalid date: ${String(date)}`);
  }
  if (timeZone) {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).formatToParts(d);
    const map = Object.fromEntries(parts.map((p) => [p.type, p.value]));
    return `${map.year}-${map.month}-${map.day}`;
  }
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}
