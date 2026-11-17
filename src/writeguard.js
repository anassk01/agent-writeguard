import { attest as attestFn, verifyAttestation as verifyAttestationFn } from './attestation.js';
import { ERROR_CODES, WriteGuardError, isWriteGuardError } from './errors.js';
import { computeFingerprint, deriveActionKey } from './fingerprint.js';
import {
  DEFAULT_KILL_SWITCH_CONFIG,
  checkCap as checkCapFn,
  clearKillSwitch as clearKillSwitchFn,
  consumeCap as consumeCapFn,
  getCapsStatus as getCapsStatusFn,
  getKillSwitch as getKillSwitchFn,
  isStopped as isStoppedFn,
  shouldTripOnError,
  tripKillSwitch as tripKillSwitchFn,
} from './governor.js';
import {
  assertIdentity as assertIdentityFn,
  bindIdentity as bindIdentityFn,
  getIdentityStatus as getIdentityStatusFn,
} from './identity.js';
import {
  LOCK_STATES,
  beginWrite as beginWriteFn,
  commitWrite as commitWriteFn,
  getLockRecord as getLockRecordFn,
  listLockRecords as listLockRecordsFn,
  markUnknown as markUnknownFn,
  reconcile as reconcileFn,
  verifyReadback as verifyReadbackFn,
} from './lock.js';
import { PolicyEngine } from './policies.js';
import {
  appendAuditLog,
  atomicWriteJson,
  ensureStateDirs,
  parseDurationMs,
  readJsonIfExists,
  resolveStatePaths,
} from './storage.js';

function serializeKillSwitchConfig(ks) {
  return {
    statusCodes: [...(ks.statusCodes || DEFAULT_KILL_SWITCH_CONFIG.statusCodes)],
    errorPatterns: (ks.errorPatterns || DEFAULT_KILL_SWITCH_CONFIG.errorPatterns).map((p) =>
      p instanceof RegExp ? { source: p.source, flags: p.flags } : String(p),
    ),
    tripOnSpendCeiling: Boolean(ks.tripOnSpendCeiling),
  };
}

function deserializeKillSwitchConfig(raw) {
  if (!raw) return { ...DEFAULT_KILL_SWITCH_CONFIG, tripOnSpendCeiling: false };
  return {
    statusCodes: Array.isArray(raw.statusCodes) ? raw.statusCodes : [...DEFAULT_KILL_SWITCH_CONFIG.statusCodes],
    errorPatterns: Array.isArray(raw.errorPatterns)
      ? raw.errorPatterns.map((p) => {
          if (p instanceof RegExp) return p;
          if (p && typeof p === 'object' && p.source) return new RegExp(p.source, p.flags || 'i');
          return new RegExp(String(p), 'i');
        })
      : [...DEFAULT_KILL_SWITCH_CONFIG.errorPatterns],
    tripOnSpendCeiling: Boolean(raw.tripOnSpendCeiling),
  };
}

export class WriteGuard {
  /**
   * @param {object} [options]
   * @param {string} [options.stateDir='.writeguard']
   * @param {number | string} [options.defaultTtlMs=86400000]
   * @param {Record<string, number>} [options.caps]
   * @param {number | null} [options.maxDailySpend]
   * @param {string} [options.timeZone]
   * @param {{ statusCodes?: number[], errorPatterns?: Array<string | RegExp>, tripOnSpendCeiling?: boolean }} [options.killSwitch]
   * @param {boolean} [options.requireAttestation=true]
   * @param {boolean} [options.requireIdentity=false]
   * @param {Array<{ name: string, check: Function }>} [options.policyRules]
   * @param {() => Date} [options.clock]
   */
  constructor(options = {}) {
    this.stateDir = options.stateDir || process.env.WRITEGUARD_DIR || '.writeguard';
    this.defaultTtlMs = options.defaultTtlMs !== undefined ? parseDurationMs(options.defaultTtlMs) : 86_400_000;
    this.caps = { ...(options.caps || {}) };
    this.maxDailySpend = options.maxDailySpend ?? null;
    this.timeZone = options.timeZone;
    this.killSwitch = deserializeKillSwitchConfig(options.killSwitch);
    this.requireAttestation = options.requireAttestation ?? true;
    this.requireIdentity = Boolean(options.requireIdentity ?? false);
    this.policyEngine = new PolicyEngine(options.policyRules || []);
    this.clock = typeof options.clock === 'function' ? options.clock : () => new Date();
  }

  now() {
    const val = this.clock();
    return val instanceof Date ? val : new Date(val);
  }

  async init(overrides = {}) {
    if (overrides.caps) this.caps = { ...this.caps, ...overrides.caps };
    if (overrides.maxDailySpend !== undefined) this.maxDailySpend = overrides.maxDailySpend;
    if (overrides.defaultTtlMs !== undefined) this.defaultTtlMs = parseDurationMs(overrides.defaultTtlMs);
    if (overrides.requireAttestation !== undefined) this.requireAttestation = Boolean(overrides.requireAttestation);
    if (overrides.requireIdentity !== undefined) this.requireIdentity = Boolean(overrides.requireIdentity);
    if (overrides.timeZone !== undefined) this.timeZone = overrides.timeZone;
    if (overrides.killSwitch) this.killSwitch = deserializeKillSwitchConfig(overrides.killSwitch);

    const paths = await ensureStateDirs(this.stateDir);
    const config = {
      version: 1,
      defaultTtlMs: this.defaultTtlMs,
      caps: this.caps,
      maxDailySpend: this.maxDailySpend,
      timeZone: this.timeZone || null,
      requireAttestation: this.requireAttestation,
      requireIdentity: this.requireIdentity,
      killSwitch: serializeKillSwitchConfig(this.killSwitch),
      updatedAt: this.now().toISOString(),
    };
    await atomicWriteJson(paths.configPath, config, 0o600);
    await appendAuditLog(this.stateDir, {
      ts: this.now().toISOString(),
      event: 'guard.initialized',
      caps: this.caps,
      maxDailySpend: this.maxDailySpend,
    });
    return config;
  }

  static async load(stateDir = process.env.WRITEGUARD_DIR || '.writeguard', overrides = {}) {
    const paths = resolveStatePaths(stateDir);
    const saved = (await readJsonIfExists(paths.configPath)) || {};
    return new WriteGuard({
      stateDir,
      defaultTtlMs: overrides.defaultTtlMs ?? saved.defaultTtlMs ?? 86_400_000,
      caps: { ...(saved.caps || {}), ...(overrides.caps || {}) },
      maxDailySpend: overrides.maxDailySpend !== undefined ? overrides.maxDailySpend : (saved.maxDailySpend ?? null),
      timeZone: overrides.timeZone ?? saved.timeZone ?? undefined,
      requireAttestation: overrides.requireAttestation ?? saved.requireAttestation ?? true,
      requireIdentity: overrides.requireIdentity ?? saved.requireIdentity ?? false,
      killSwitch: overrides.killSwitch ?? saved.killSwitch,
      policyRules: overrides.policyRules || [],
      clock: overrides.clock,
    });
  }

  addPolicyRule(rule) {
    this.policyEngine.addPolicyRule(rule);
    return this;
  }

  async evaluatePolicies(ctx) {
    return this.policyEngine.evaluate(ctx);
  }

  async bindIdentity({ identity, label = 'default', force = false }) {
    return bindIdentityFn(this.stateDir, { identity, label, force, now: this.now() });
  }

  async assertIdentity(candidateIdentity) {
    return assertIdentityFn(this.stateDir, candidateIdentity, { now: this.now() });
  }

  async attest({ action, target, payload = null, ttlMs, actor = 'agent', metadata = {} }) {
    return attestFn(this.stateDir, {
      action,
      target,
      payload,
      ttlMs: ttlMs ?? this.defaultTtlMs,
      actor,
      metadata,
      now: this.now(),
    });
  }

  async verifyAttestation({ attestationId, action, target, payload = null }) {
    return verifyAttestationFn(this.stateDir, {
      attestationId,
      action,
      target,
      payload,
      now: this.now(),
    });
  }

  async isStopped() {
    return isStoppedFn(this.stateDir);
  }

  async getKillSwitch() {
    return getKillSwitchFn(this.stateDir);
  }

  async tripKillSwitch({ reason, signal = 'MANUAL', actionKey = null, metadata = {} } = {}) {
    return tripKillSwitchFn(this.stateDir, {
      reason,
      signal,
      actionKey,
      metadata,
      now: this.now(),
    });
  }

  async clearKillSwitch({ operator = 'operator', reason = 'Cleared after review' } = {}) {
    return clearKillSwitchFn(this.stateDir, {
      operator,
      reason,
      now: this.now(),
    });
  }

  async checkCap({ action, amount = 0 }) {
    return checkCapFn(this.stateDir, {
      action,
      amount,
      caps: this.caps,
      maxDailySpend: this.maxDailySpend,
      now: this.now(),
      timeZone: this.timeZone,
    });
  }

  async getCaps() {
    return getCapsStatusFn(this.stateDir, {
      caps: this.caps,
      maxDailySpend: this.maxDailySpend,
      now: this.now(),
      timeZone: this.timeZone,
    });
  }

  /**
   * Executes all pre-flight safety gates (STOP kill switch -> salted identity -> policy/PII gate ->
   * dry-run attestation -> daily cap) and atomically acquires the O_EXCL (`wx`) pending lock.
   */
  async beginWrite({
    actionKey,
    action,
    target,
    payload = null,
    attestationId = null,
    identity,
    amount = 0,
    requireAttestation,
    allowReconciledRetry = false,
    metadata = {},
  }) {
    const now = this.now();

    // 1. STOP kill switch check (always first, fail closed).
    const stopRecord = await getKillSwitchFn(this.stateDir);
    if (stopRecord) {
      throw new WriteGuardError(
        ERROR_CODES.ERR_KILL_SWITCH_ACTIVE,
        `Write blocked by STOP kill switch (${stopRecord.signal}): ${stopRecord.reason}`,
        { details: { killSwitch: stopRecord } },
      );
    }

    // 2. Salted identity binding check (if bound or required).
    const idStatus = await getIdentityStatusFn(this.stateDir);
    if (this.requireIdentity || idStatus.bound) {
      await assertIdentityFn(this.stateDir, identity, { now });
    }

    // 3. Pluggable policy & PII gate.
    const policyResult = await this.policyEngine.evaluate({
      action,
      target,
      payload,
      amount: amount || undefined,
      identity,
      metadata,
    });
    if (!policyResult.allowed) {
      await appendAuditLog(this.stateDir, {
        ts: now.toISOString(),
        event: 'policy.blocked',
        action,
        target,
        violations: policyResult.violations,
      });
      throw new WriteGuardError(
        ERROR_CODES.ERR_POLICY_VIOLATION,
        `Write blocked by policy (${policyResult.violations[0].rule}): ${policyResult.violations[0].reason}`,
        { details: { violations: policyResult.violations } },
      );
    }

    // 4. Fingerprint-bound dry-run attestation check.
    const mustAttest = requireAttestation ?? this.requireAttestation;
    const fingerprint = computeFingerprint({ action, target, payload });
    if (mustAttest) {
      await verifyAttestationFn(this.stateDir, {
        attestationId,
        action,
        target,
        payload,
        now,
      });
    }

    // 5. Pre-check daily cap & spend ceiling before acquiring lock.
    const capCheck = await checkCapFn(this.stateDir, {
      action,
      amount,
      caps: this.caps,
      maxDailySpend: this.maxDailySpend,
      now,
      timeZone: this.timeZone,
    });
    if (!capCheck.allowed) {
      if (capCheck.code === ERROR_CODES.ERR_SPEND_CEILING_EXCEEDED && this.killSwitch.tripOnSpendCeiling) {
        await tripKillSwitchFn(this.stateDir, {
          reason: capCheck.reason,
          signal: 'SPEND_CEILING',
          actionKey: deriveActionKey({ actionKey, action, target, fingerprint }),
          now,
        });
      }
      throw new WriteGuardError(capCheck.code, capCheck.reason, { details: capCheck });
    }

    // 6. Atomic O_EXCL ('wx') pending lock BEFORE side effect!
    const lockRecord = await beginWriteFn(this.stateDir, {
      actionKey,
      action,
      target,
      payload,
      fingerprint,
      attestationId,
      metadata: { ...metadata, amount },
      allowReconciledRetry,
      now,
    });

    // 7. Record daily cap consumption now that lock ownership is guaranteed.
    await consumeCapFn(this.stateDir, {
      action,
      amount,
      caps: this.caps,
      maxDailySpend: this.maxDailySpend,
      tripOnSpendCeiling: this.killSwitch.tripOnSpendCeiling,
      now,
      timeZone: this.timeZone,
    });

    return lockRecord;
  }

  async commitWrite(actionKey, { result = null, verification } = {}) {
    return commitWriteFn(this.stateDir, actionKey, {
      result,
      verification,
      now: this.now(),
    });
  }

  async markUnknown(actionKey, { error, reason, signal } = {}) {
    const now = this.now();
    const trigger = shouldTripOnError(error ?? reason, this.killSwitch);
    const updated = await markUnknownFn(this.stateDir, actionKey, {
      error,
      reason,
      signal: signal || (trigger.shouldTrip ? trigger.signal : null),
      now,
    });
    if (trigger.shouldTrip) {
      await tripKillSwitchFn(this.stateDir, {
        reason: trigger.reason,
        signal: trigger.signal,
        actionKey: updated.actionKey,
        now,
      });
    }
    return updated;
  }

  async verifyReadback(actionKey, verifierFn, { context } = {}) {
    return verifyReadbackFn(this.stateDir, actionKey, verifierFn, {
      context,
      now: this.now(),
    });
  }

  async reconcile(actionKey, verifierOrDecision, { operator = 'reconciler' } = {}) {
    return reconcileFn(this.stateDir, actionKey, verifierOrDecision, {
      operator,
      now: this.now(),
    });
  }

  /**
   * High-level all-in-one non-idempotent execution wrapper:
   * 1) beginWrite (kill switch, identity, policy, attestation, daily cap, O_EXCL lock)
   * 2) execute()
   * 3) on throw/timeout -> markUnknown (+ auto-trip kill switch on matching signals)
   * 4) mandatory verifyReadback() -> committed_verified (or outcome_unknown)
   */
  async guardWrite({
    actionKey,
    action,
    target,
    payload = null,
    attestationId = null,
    identity,
    amount = 0,
    requireAttestation,
    allowReconciledRetry = false,
    unsafeSkipReadback = false,
    metadata = {},
    execute,
    verifyReadback,
  }) {
    if (typeof execute !== 'function') {
      throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'guardWrite requires an execute() function.');
    }
    if (!unsafeSkipReadback && typeof verifyReadback !== 'function') {
      throw new WriteGuardError(
        ERROR_CODES.ERR_READBACK_REQUIRED,
        'guardWrite requires a verifyReadback() hook. Pass unsafeSkipReadback=true only if read-back is impossible.',
      );
    }

    const lock = await this.beginWrite({
      actionKey,
      action,
      target,
      payload,
      attestationId,
      identity,
      amount,
      requireAttestation,
      allowReconciledRetry,
      metadata,
    });

    let executionResult;
    try {
      executionResult = await execute({ lock, action, target, payload });
    } catch (err) {
      const trigger = shouldTripOnError(err, this.killSwitch);
      await this.markUnknown(lock.actionKey, {
        error: err,
        reason: err instanceof Error ? err.message : String(err),
        signal: trigger.shouldTrip ? trigger.signal : 'EXECUTION_ERROR',
      });
      if (isWriteGuardError(err)) {
        throw err;
      }
      throw new WriteGuardError(
        ERROR_CODES.ERR_EXECUTION_FAILED,
        `Side effect failed or timed out for "${lock.actionKey}". Lock marked outcome_unknown; DO NOT blind-retry without reconcile(). Cause: ${err instanceof Error ? err.message : String(err)}`,
        {
          outcomeUnknown: true,
          retryable: false,
          cause: err,
          details: {
            actionKey: lock.actionKey,
            killSwitchTripped: trigger.shouldTrip,
            killSwitchSignal: trigger.signal || null,
          },
        },
      );
    }

    if (unsafeSkipReadback) {
      const committed = await this.commitWrite(lock.actionKey, {
        result: executionResult,
        verification: { verified: true, evidence: { skipped: true, warning: 'unsafeSkipReadback=true' } },
      });
      return { record: committed, result: executionResult };
    }

    await this.commitWrite(lock.actionKey, { result: executionResult });
    const verified = await this.verifyReadback(lock.actionKey, verifyReadback, {
      context: { result: executionResult, action, target, payload },
    });
    return { record: verified, result: executionResult };
  }

  async status(actionKey) {
    const [killSwitch, identity, caps, records] = await Promise.all([
      getKillSwitchFn(this.stateDir),
      getIdentityStatusFn(this.stateDir),
      this.getCaps(),
      actionKey
        ? getLockRecordFn(this.stateDir, actionKey).then((r) => (r ? [r] : []))
        : listLockRecordsFn(this.stateDir),
    ]);

    const summary = {
      total: records.length,
      [LOCK_STATES.PENDING]: 0,
      [LOCK_STATES.COMMITTED_UNVERIFIED]: 0,
      [LOCK_STATES.COMMITTED_VERIFIED]: 0,
      [LOCK_STATES.OUTCOME_UNKNOWN]: 0,
      [LOCK_STATES.RECONCILED_ABORTED]: 0,
    };
    for (const r of records) {
      if (Object.prototype.hasOwnProperty.call(summary, r.state)) {
        summary[r.state] += 1;
      }
    }

    return {
      stateDir: resolveStatePaths(this.stateDir).root,
      stopped: Boolean(killSwitch),
      killSwitch,
      identity,
      caps,
      summary,
      records,
    };
  }
}
