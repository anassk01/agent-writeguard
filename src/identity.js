import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { ERROR_CODES, WriteGuardError } from './errors.js';
import { canonicalize } from './fingerprint.js';
import {
  appendAuditLog,
  atomicWriteJson,
  ensureStateDirs,
  readJsonIfExists,
  resolveStatePaths,
} from './storage.js';

function normalizeIdentityInput(identity) {
  if (typeof identity === 'string') {
    const trimmed = identity.trim();
    if (!trimmed) {
      throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'identity must be a non-empty string or object.');
    }
    return trimmed;
  }
  if (identity && typeof identity === 'object') {
    return canonicalize(identity);
  }
  throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'identity must be a non-empty string or object.');
}

function hashWithSalt(saltHex, normalizedIdentity) {
  return createHash('sha256')
    .update(`${saltHex}:${normalizedIdentity}`, 'utf8')
    .digest('hex');
}

/**
 * Binds this WriteGuard state directory to a cryptographically salted identity hash
 * (e.g. tenant ID, account ID, environment tuple). Never stores plaintext identity on disk.
 *
 * @param {string} stateDir
 * @param {{ identity: string | object, label?: string, force?: boolean, now?: Date }} options
 */
export async function bindIdentity(stateDir, { identity, label = 'default', force = false, now = new Date() } = {}) {
  const normalized = normalizeIdentityInput(identity);
  const paths = await ensureStateDirs(stateDir);
  const existing = await readJsonIfExists(paths.identityPath);
  if (existing && !force) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_INVALID_STATE_TRANSITION,
      `Identity is already bound (label="${existing.label}"). Pass force=true to rebind.`,
      { details: { label: existing.label, boundAt: existing.boundAt } },
    );
  }

  const saltHex = randomBytes(32).toString('hex');
  const hashHex = hashWithSalt(saltHex, normalized);
  const record = {
    version: 1,
    algorithm: 'sha256-salted',
    label: String(label || 'default'),
    saltHex,
    hashHex,
    boundAt: now.toISOString(),
  };

  await atomicWriteJson(paths.identityPath, record, 0o600);
  await appendAuditLog(stateDir, {
    ts: now.toISOString(),
    event: 'identity.bound',
    label: record.label,
    hashPrefix: hashHex.slice(0, 12),
    rebound: Boolean(existing),
  });

  return {
    bound: true,
    label: record.label,
    boundAt: record.boundAt,
    hashPrefix: hashHex.slice(0, 12),
  };
}

/**
 * Verifies a candidate identity against the stored salted hash using constant-time comparison.
 * Throws ERR_IDENTITY_NOT_BOUND or ERR_IDENTITY_MISMATCH on failure.
 *
 * @param {string} stateDir
 * @param {string | object} candidateIdentity
 * @param {{ now?: Date }} [options]
 */
export async function assertIdentity(stateDir, candidateIdentity, { now = new Date() } = {}) {
  const paths = resolveStatePaths(stateDir);
  const record = await readJsonIfExists(paths.identityPath);
  if (!record || !record.saltHex || !record.hashHex) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_IDENTITY_NOT_BOUND,
      'No identity is bound for this WriteGuard state directory. Run bindIdentity() first.',
    );
  }

  if (candidateIdentity === undefined || candidateIdentity === null || candidateIdentity === '') {
    throw new WriteGuardError(
      ERROR_CODES.ERR_IDENTITY_MISMATCH,
      `Identity verification failed: candidate identity is missing (expected bound label "${record.label}").`,
      { details: { label: record.label } },
    );
  }

  const normalized = normalizeIdentityInput(candidateIdentity);
  const candidateHash = hashWithSalt(record.saltHex, normalized);
  const expectedBuf = Buffer.from(record.hashHex, 'hex');
  const candidateBuf = Buffer.from(candidateHash, 'hex');

  const matches = expectedBuf.length === candidateBuf.length && timingSafeEqual(expectedBuf, candidateBuf);
  if (!matches) {
    await appendAuditLog(stateDir, {
      ts: now.toISOString(),
      event: 'identity.mismatch',
      label: record.label,
    });
    throw new WriteGuardError(
      ERROR_CODES.ERR_IDENTITY_MISMATCH,
      `Identity mismatch: refusing cross-account/wrong-tenant mutation (expected bound label "${record.label}").`,
      { details: { label: record.label } },
    );
  }

  return {
    verified: true,
    label: record.label,
    hashPrefix: record.hashHex.slice(0, 12),
  };
}

/**
 * Returns non-sensitive status of identity binding.
 *
 * @param {string} stateDir
 */
export async function getIdentityStatus(stateDir) {
  const paths = resolveStatePaths(stateDir);
  const record = await readJsonIfExists(paths.identityPath);
  if (!record) {
    return { bound: false, label: null, boundAt: null, hashPrefix: null };
  }
  return {
    bound: true,
    label: record.label,
    boundAt: record.boundAt,
    hashPrefix: record.hashHex ? record.hashHex.slice(0, 12) : null,
  };
}
