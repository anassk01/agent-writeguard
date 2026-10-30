import { createHash } from 'node:crypto';
import { ERROR_CODES, WriteGuardError } from './errors.js';

/**
 * Normalize a value into a deterministic, canonical structure suitable for SHA-256 hashing.
 * Object keys are recursively sorted, `undefined` object properties are stripped, and
 * circular references fail loudly.
 *
 * @param {unknown} value
 * @param {WeakSet<object>} [seen]
 * @returns {unknown}
 */
export function normalizeValue(value, seen = new WeakSet()) {
  if (value === null || value === undefined) {
    return null;
  }

  const type = typeof value;
  if (type === 'boolean' || type === 'string') {
    return value;
  }
  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new WriteGuardError(
        ERROR_CODES.ERR_INVALID_ARGUMENT,
        `Non-finite number (${String(value)}) cannot be fingerprinted.`,
      );
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (type === 'bigint') {
    return { $bigint: value.toString() };
  }
  if (type === 'function' || type === 'symbol') {
    throw new WriteGuardError(
      ERROR_CODES.ERR_INVALID_ARGUMENT,
      `Unsupported value type "${type}" in payload fingerprinting.`,
    );
  }

  if (value instanceof Date) {
    return { $date: value.toISOString() };
  }
  if (value instanceof RegExp) {
    return { $regexp: value.toString() };
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return { $bytes: Buffer.from(value).toString('base64') };
  }

  if (seen.has(value)) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_INVALID_ARGUMENT,
      'Circular reference detected while normalizing action payload.',
    );
  }
  seen.add(value);

  try {
    if (Array.isArray(value)) {
      return value.map((item) => normalizeValue(item, seen));
    }

    const out = {};
    const keys = Object.keys(value).sort();
    for (const key of keys) {
      const prop = value[key];
      if (prop === undefined) continue;
      out[key] = normalizeValue(prop, seen);
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

/**
 * Deterministic canonical JSON string.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  return JSON.stringify(normalizeValue(value));
}

/**
 * Computes a SHA-256 fingerprint bound to action + target + normalized payload.
 *
 * @param {{ action: string, target: string, payload?: unknown }} input
 * @returns {string} `sha256:<hex>`
 */
export function computeFingerprint({ action, target, payload = null }) {
  if (typeof action !== 'string' || action.trim() === '') {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'action must be a non-empty string.');
  }
  if (typeof target !== 'string' || target.trim() === '') {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'target must be a non-empty string.');
  }
  const canonical = canonicalize({
    action: action.trim(),
    target: target.trim(),
    payload,
  });
  const digest = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return `sha256:${digest}`;
}

/**
 * Produces a filesystem-safe, deterministic action key without path traversal risks.
 *
 * @param {{ actionKey?: string, action: string, target: string, fingerprint?: string }} input
 * @returns {string}
 */
export function deriveActionKey({ actionKey, action, target, fingerprint }) {
  if (actionKey !== undefined && actionKey !== null) {
    if (typeof actionKey !== 'string' || actionKey.trim() === '') {
      throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'actionKey must be a non-empty string when provided.');
    }
    const trimmed = actionKey.trim();
    if (/^[a-zA-Z0-9._-]{1,120}$/.test(trimmed) && !trimmed.includes('..') && !trimmed.startsWith('.')) {
      return trimmed;
    }
    const slug = trimmed
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 40) || 'action';
    const hash = createHash('sha256').update(trimmed, 'utf8').digest('hex').slice(0, 16);
    return `${slug}-${hash}`;
  }

  const slug = `${action}-${target}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40) || 'action';
  const source = fingerprint || computeFingerprint({ action, target, payload: null });
  const hash = createHash('sha256').update(source, 'utf8').digest('hex').slice(0, 16);
  return `${slug}-${hash}`;
}

/**
 * Lightweight structural diff between two normalized payloads to explain drift.
 *
 * @param {unknown} expected
 * @param {unknown} actual
 * @param {string} [prefix]
 * @returns {Array<{ path: string, kind: 'added' | 'removed' | 'changed' }>}
 */
export function diffPayloadSummary(expected, actual, prefix = '') {
  const normA = normalizeValue(expected);
  const normB = normalizeValue(actual);
  return diffNormalized(normA, normB, prefix);
}

function diffNormalized(a, b, prefix) {
  if (JSON.stringify(a) === JSON.stringify(b)) {
    return [];
  }

  const isObjA = a !== null && typeof a === 'object' && !Array.isArray(a);
  const isObjB = b !== null && typeof b === 'object' && !Array.isArray(b);

  if (!isObjA || !isObjB) {
    return [{ path: prefix || '$', kind: 'changed' }];
  }

  const diffs = [];
  const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const key of [...allKeys].sort()) {
    const nextPath = prefix ? `${prefix}.${key}` : key;
    const hasA = Object.prototype.hasOwnProperty.call(a, key);
    const hasB = Object.prototype.hasOwnProperty.call(b, key);
    if (hasA && !hasB) {
      diffs.push({ path: nextPath, kind: 'removed' });
    } else if (!hasA && hasB) {
      diffs.push({ path: nextPath, kind: 'added' });
    } else {
      diffs.push(...diffNormalized(a[key], b[key], nextPath));
    }
  }
  return diffs;
}
