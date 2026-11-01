import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { ERROR_CODES, WriteGuardError } from './errors.js';
import {
  computeFingerprint,
  diffPayloadSummary,
  normalizeValue,
} from './fingerprint.js';
import {
  appendAuditLog,
  atomicWriteJson,
  ensureStateDirs,
  parseDurationMs,
  readJsonIfExists,
  resolveStatePaths,
} from './storage.js';

const DEFAULT_TTL_MS = 86_400_000; // 24h

function sanitizeAttestationId(attestationId) {
  if (typeof attestationId !== 'string' || !/^att_[a-f0-9]{16,64}$/.test(attestationId.trim())) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_ATTESTATION_MISSING,
      `Invalid attestationId format: "${String(attestationId)}".`,
    );
  }
  return attestationId.trim();
}

/**
 * Creates a fingerprint-bound dry-run attestation for a planned non-idempotent action.
 *
 * @param {string} stateDir
 * @param {{ action: string, target: string, payload?: unknown, ttlMs?: number | string, actor?: string, metadata?: object, now?: Date }} options
 */
export async function attest(
  stateDir,
  { action, target, payload = null, ttlMs = DEFAULT_TTL_MS, actor = 'agent', metadata = {}, now = new Date() } = {},
) {
  const resolvedTtlMs = parseDurationMs(ttlMs);
  const fingerprint = computeFingerprint({ action, target, payload });
  const attestationId = `att_${randomBytes(10).toString('hex')}`;
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + resolvedTtlMs).toISOString();

  const paths = await ensureStateDirs(stateDir);
  const record = {
    version: 1,
    attestationId,
    action: action.trim(),
    target: target.trim(),
    fingerprint,
    normalizedPayload: normalizeValue(payload),
    actor: String(actor),
    ttlMs: resolvedTtlMs,
    createdAt,
    expiresAt,
    metadata,
  };

  await atomicWriteJson(join(paths.attestationsDir, `${attestationId}.json`), record, 0o600);
  await appendAuditLog(stateDir, {
    ts: createdAt,
    event: 'attestation.created',
    attestationId,
    action: record.action,
    target: record.target,
    fingerprint,
    expiresAt,
    actor: record.actor,
  });

  return record;
}

/**
 * Verifies that a dry-run attestation exists, has not expired, and matches the exact
 * action, target, and normalized payload SHA-256 fingerprint.
 *
 * @param {string} stateDir
 * @param {{ attestationId: string, action: string, target: string, payload?: unknown, now?: Date }} options
 */
export async function verifyAttestation(
  stateDir,
  { attestationId, action, target, payload = null, now = new Date() } = {},
) {
  if (!attestationId) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_ATTESTATION_MISSING,
      'Live write refused: missing dry-run attestationId. Run attest() first.',
    );
  }

  const safeId = sanitizeAttestationId(attestationId);
  const paths = resolveStatePaths(stateDir);
  const record = await readJsonIfExists(join(paths.attestationsDir, `${safeId}.json`));
  if (!record) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_ATTESTATION_MISSING,
      `Dry-run attestation "${safeId}" not found.`,
      { details: { attestationId: safeId } },
    );
  }

  const expiresMs = Date.parse(record.expiresAt);
  if (Number.isNaN(expiresMs) || now.getTime() > expiresMs) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_ATTESTATION_EXPIRED,
      `Dry-run attestation "${safeId}" expired at ${record.expiresAt}. Re-attest before executing.`,
      {
        details: {
          attestationId: safeId,
          expiresAt: record.expiresAt,
          now: now.toISOString(),
        },
      },
    );
  }

  const actualFingerprint = computeFingerprint({ action, target, payload });
  if (record.fingerprint !== actualFingerprint) {
    const payloadDiff = diffPayloadSummary(record.normalizedPayload, payload);
    const targetDrifted = record.target !== target.trim();
    const actionDrifted = record.action !== action.trim();
    throw new WriteGuardError(
      ERROR_CODES.ERR_ATTESTATION_DRIFT,
      `Live write refused: payload or target drifted from dry-run attestation "${safeId}".`,
      {
        details: {
          attestationId: safeId,
          expectedFingerprint: record.fingerprint,
          actualFingerprint,
          actionDrifted,
          targetDrifted,
          payloadDiff,
        },
      },
    );
  }

  return {
    verified: true,
    attestationId: safeId,
    fingerprint: record.fingerprint,
    expiresAt: record.expiresAt,
    record,
  };
}
