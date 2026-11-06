import { open, readdir, rename, unlink } from 'node:fs/promises';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { ERROR_CODES, WriteGuardError } from './errors.js';
import { computeFingerprint, deriveActionKey } from './fingerprint.js';
import {
  appendAuditLog,
  atomicWriteJson,
  ensureStateDirs,
  readJsonIfExists,
  resolveStatePaths,
} from './storage.js';

export const LOCK_STATES = Object.freeze({
  PENDING: 'pending',
  COMMITTED_UNVERIFIED: 'committed_unverified',
  COMMITTED_VERIFIED: 'committed_verified',
  OUTCOME_UNKNOWN: 'outcome_unknown',
  RECONCILED_ABORTED: 'reconciled_aborted',
});

function lockPathFor(stateDir, safeKey) {
  const paths = resolveStatePaths(stateDir);
  return join(paths.locksDir, `${safeKey}.json`);
}

function validateSafeKey(actionKey) {
  if (typeof actionKey !== 'string' || actionKey.trim() === '') {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'actionKey must be a non-empty string.');
  }
  const safe = deriveActionKey({ actionKey, action: 'action', target: 'target' });
  return safe;
}

/**
 * Atomically creates a pending lock record via OS-level O_EXCL (`wx`) BEFORE
 * executing any non-idempotent side effect.
 *
 * @param {string} stateDir
 * @param {{ actionKey?: string, action: string, target: string, payload?: unknown, fingerprint?: string, attestationId?: string | null, metadata?: object, allowReconciledRetry?: boolean, now?: Date }} options
 */
export async function beginWrite(
  stateDir,
  {
    actionKey,
    action,
    target,
    payload = null,
    fingerprint,
    attestationId = null,
    metadata = {},
    allowReconciledRetry = false,
    now = new Date(),
  } = {},
) {
  const computedFingerprint = fingerprint || computeFingerprint({ action, target, payload });
  const safeKey = deriveActionKey({ actionKey, action, target, fingerprint: computedFingerprint });
  const paths = await ensureStateDirs(stateDir);
  const lockFile = join(paths.locksDir, `${safeKey}.json`);

  const createPendingFile = async () => {
    const record = {
      version: 1,
      actionKey: safeKey,
      state: LOCK_STATES.PENDING,
      action: action.trim(),
      target: target.trim(),
      fingerprint: computedFingerprint,
      attestationId,
      pid: process.pid,
      host: hostname(),
      startedAt: now.toISOString(),
      updatedAt: now.toISOString(),
      metadata,
      history: [
        {
          state: LOCK_STATES.PENDING,
          ts: now.toISOString(),
          note: 'Atomic O_EXCL lock acquired before side effect.',
        },
      ],
    };

    const raw = `${JSON.stringify(record, null, 2)}\n`;
    let handle;
    try {
      // OS-level O_CREAT | O_EXCL ('wx'): guaranteed atomic across processes & concurrent promises.
      handle = await open(lockFile, 'wx', 0o600);
      await handle.writeFile(raw, 'utf8');
      await handle.sync();
      await handle.close();
      handle = null;
      return record;
    } catch (err) {
      if (handle) {
        await handle.close().catch(() => {});
        await unlink(lockFile).catch(() => {});
      }
      throw err;
    }
  };

  try {
    const record = await createPendingFile();
    await appendAuditLog(stateDir, {
      ts: now.toISOString(),
      event: 'lock.begin',
      actionKey: safeKey,
      action: record.action,
      target: record.target,
      fingerprint: computedFingerprint,
      attestationId,
    });
    return record;
  } catch (err) {
    if (err?.code !== 'EEXIST') {
      throw err;
    }

    const existing = await readJsonIfExists(lockFile);
    if (!existing) {
      // Another writer just created the lock file and is flushing bytes right now.
      throw new WriteGuardError(
        ERROR_CODES.ERR_WRITE_IN_FLIGHT,
        `Write "${safeKey}" is already in flight (lock file exists).`,
        { details: { actionKey: safeKey } },
      );
    }

    if (existing.state === LOCK_STATES.RECONCILED_ABORTED && allowReconciledRetry) {
      const archivePath = join(paths.archiveDir, `${safeKey}-${now.getTime()}.json`);
      await rename(lockFile, archivePath);
      const record = await createPendingFile();
      await appendAuditLog(stateDir, {
        ts: now.toISOString(),
        event: 'lock.retry_after_reconcile',
        actionKey: safeKey,
        archivedPrevious: archivePath,
      });
      return record;
    }

    if (existing.state === LOCK_STATES.PENDING) {
      throw new WriteGuardError(
        ERROR_CODES.ERR_WRITE_IN_FLIGHT,
        `Write "${safeKey}" is already in flight (pid=${existing.pid}, startedAt=${existing.startedAt}).`,
        { details: { actionKey: safeKey, existingState: existing.state, startedAt: existing.startedAt } },
      );
    }

    if (existing.state === LOCK_STATES.OUTCOME_UNKNOWN) {
      throw new WriteGuardError(
        ERROR_CODES.ERR_OUTCOME_UNKNOWN,
        `HARD BLOCK: Write "${safeKey}" is in outcome_unknown state. Blind retries are forbidden until reconciled via fresh read-back verification.`,
        {
          outcomeUnknown: true,
          retryable: false,
          details: {
            actionKey: safeKey,
            existingState: existing.state,
            reason: existing.unknownReason || null,
            updatedAt: existing.updatedAt,
          },
        },
      );
    }

    if (existing.state === LOCK_STATES.COMMITTED_VERIFIED || existing.state === LOCK_STATES.COMMITTED_UNVERIFIED) {
      throw new WriteGuardError(
        ERROR_CODES.ERR_ALREADY_COMMITTED,
        `Idempotency guard: Write "${safeKey}" already completed with state "${existing.state}".`,
        { details: { actionKey: safeKey, existingState: existing.state, committedAt: existing.committedAt } },
      );
    }

    throw new WriteGuardError(
      ERROR_CODES.ERR_INVALID_STATE_TRANSITION,
      `Write "${safeKey}" exists in state "${existing.state}". Pass allowReconciledRetry=true to retry a reconciled_aborted action.`,
      { details: { actionKey: safeKey, existingState: existing.state } },
    );
  }
}

/**
 * Transitions a pending/unverified record to `outcome_unknown`, permanently blocking blind
 * retries until reconciled against external source-of-truth read-back.
 *
 * @param {string} stateDir
 * @param {string} actionKey
 * @param {{ error?: unknown, reason?: string, signal?: string, now?: Date }} [options]
 */
export async function markUnknown(stateDir, actionKey, { error, reason, signal, now = new Date() } = {}) {
  const safeKey = validateSafeKey(actionKey);
  const lockFile = lockPathFor(stateDir, safeKey);
  const record = await readJsonIfExists(lockFile);
  if (!record) {
    throw new WriteGuardError(ERROR_CODES.ERR_RECORD_NOT_FOUND, `Lock record "${safeKey}" not found.`);
  }
  if (record.state === LOCK_STATES.COMMITTED_VERIFIED) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_INVALID_STATE_TRANSITION,
      `Cannot mark already committed_verified record "${safeKey}" as outcome_unknown.`,
    );
  }

  const errorMessage =
    reason ||
    (error instanceof Error ? error.message : typeof error === 'string' ? error : 'Ambiguous failure or timeout mid-flight');

  const updated = {
    ...record,
    state: LOCK_STATES.OUTCOME_UNKNOWN,
    unknownReason: errorMessage,
    unknownSignal: signal || null,
    updatedAt: now.toISOString(),
    history: [
      ...(record.history || []),
      {
        state: LOCK_STATES.OUTCOME_UNKNOWN,
        ts: now.toISOString(),
        note: errorMessage,
        signal: signal || null,
      },
    ],
  };

  await atomicWriteJson(lockFile, updated, 0o600);
  await appendAuditLog(stateDir, {
    ts: now.toISOString(),
    event: 'lock.outcome_unknown',
    actionKey: safeKey,
    reason: errorMessage,
    signal: signal || null,
  });
  return updated;
}

/**
 * Records side-effect completion. Remains `committed_unverified` until `verifyReadback`
 * confirms external state, unless verified evidence is supplied.
 *
 * @param {string} stateDir
 * @param {string} actionKey
 * @param {{ result?: unknown, verification?: { verified: boolean, evidence?: unknown }, now?: Date }} [options]
 */
export async function commitWrite(stateDir, actionKey, { result = null, verification, now = new Date() } = {}) {
  const safeKey = validateSafeKey(actionKey);
  const lockFile = lockPathFor(stateDir, safeKey);
  const record = await readJsonIfExists(lockFile);
  if (!record) {
    throw new WriteGuardError(ERROR_CODES.ERR_RECORD_NOT_FOUND, `Lock record "${safeKey}" not found.`);
  }
  if (record.state !== LOCK_STATES.PENDING && record.state !== LOCK_STATES.COMMITTED_UNVERIFIED) {
    throw new WriteGuardError(
      ERROR_CODES.ERR_INVALID_STATE_TRANSITION,
      `Cannot commit write "${safeKey}" from state "${record.state}".`,
      { details: { actionKey: safeKey, state: record.state } },
    );
  }

  const isVerified = Boolean(verification && verification.verified === true);
  const nextState = isVerified ? LOCK_STATES.COMMITTED_VERIFIED : LOCK_STATES.COMMITTED_UNVERIFIED;

  const updated = {
    ...record,
    state: nextState,
    result,
    committedAt: record.committedAt || now.toISOString(),
    verifiedAt: isVerified ? now.toISOString() : null,
    verificationEvidence: isVerified ? (verification.evidence ?? null) : null,
    updatedAt: now.toISOString(),
    history: [
      ...(record.history || []),
      {
        state: nextState,
        ts: now.toISOString(),
        note: isVerified ? 'Committed and verified via read-back.' : 'Side effect returned; awaiting read-back verification.',
      },
    ],
  };

  await atomicWriteJson(lockFile, updated, 0o600);
  await appendAuditLog(stateDir, {
    ts: now.toISOString(),
    event: isVerified ? 'lock.committed_verified' : 'lock.committed_unverified',
    actionKey: safeKey,
  });
  return updated;
}

export async function getLockRecord(stateDir, actionKey) {
  const safeKey = validateSafeKey(actionKey);
  return readJsonIfExists(lockPathFor(stateDir, safeKey));
}

export async function listLockRecords(stateDir) {
  const paths = resolveStatePaths(stateDir);
  let files;
  try {
    files = await readdir(paths.locksDir);
  } catch (err) {
    if (err?.code === 'ENOENT') return [];
    throw err;
  }
  const records = [];
  for (const file of files.sort()) {
    if (!file.endsWith('.json')) continue;
    const rec = await readJsonIfExists(join(paths.locksDir, file));
    if (rec) records.push(rec);
  }
  return records;
}
