export declare const ERROR_CODES: Readonly<{
  ERR_KILL_SWITCH_ACTIVE: 'ERR_KILL_SWITCH_ACTIVE';
  ERR_IDENTITY_NOT_BOUND: 'ERR_IDENTITY_NOT_BOUND';
  ERR_IDENTITY_MISMATCH: 'ERR_IDENTITY_MISMATCH';
  ERR_POLICY_VIOLATION: 'ERR_POLICY_VIOLATION';
  ERR_ATTESTATION_MISSING: 'ERR_ATTESTATION_MISSING';
  ERR_ATTESTATION_EXPIRED: 'ERR_ATTESTATION_EXPIRED';
  ERR_ATTESTATION_DRIFT: 'ERR_ATTESTATION_DRIFT';
  ERR_DAILY_CAP_EXCEEDED: 'ERR_DAILY_CAP_EXCEEDED';
  ERR_SPEND_CEILING_EXCEEDED: 'ERR_SPEND_CEILING_EXCEEDED';
  ERR_WRITE_IN_FLIGHT: 'ERR_WRITE_IN_FLIGHT';
  ERR_OUTCOME_UNKNOWN: 'ERR_OUTCOME_UNKNOWN';
  ERR_ALREADY_COMMITTED: 'ERR_ALREADY_COMMITTED';
  ERR_RECORD_NOT_FOUND: 'ERR_RECORD_NOT_FOUND';
  ERR_INVALID_STATE_TRANSITION: 'ERR_INVALID_STATE_TRANSITION';
  ERR_READBACK_REQUIRED: 'ERR_READBACK_REQUIRED';
  ERR_READBACK_FAILED: 'ERR_READBACK_FAILED';
  ERR_EXECUTION_FAILED: 'ERR_EXECUTION_FAILED';
  ERR_INVALID_ARGUMENT: 'ERR_INVALID_ARGUMENT';
}>;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

export declare const LOCK_STATES: Readonly<{
  PENDING: 'pending';
  COMMITTED_UNVERIFIED: 'committed_unverified';
  COMMITTED_VERIFIED: 'committed_verified';
  OUTCOME_UNKNOWN: 'outcome_unknown';
  RECONCILED_ABORTED: 'reconciled_aborted';
}>;

export type LockState = (typeof LOCK_STATES)[keyof typeof LOCK_STATES];

export declare class WriteGuardError extends Error {
  code: ErrorCode | string;
  details: Record<string, unknown>;
  retryable: boolean;
  outcomeUnknown: boolean;
  constructor(
    code: string,
    message: string,
    options?: {
      details?: Record<string, unknown>;
      retryable?: boolean;
      outcomeUnknown?: boolean;
      cause?: unknown;
    },
  );
  toJSON(): Record<string, unknown>;
}

export declare function isWriteGuardError(err: unknown): err is WriteGuardError;

export interface PolicyContext {
  action: string;
  target: string;
  payload: unknown;
  amount?: number;
  identity?: string | Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface PolicyCheckResult {
  allowed: boolean;
  reason?: string;
  path?: string;
  violations?: Array<{ path: string; reason: string }>;
}

export interface PolicyRule {
  name: string;
  check: (ctx: PolicyContext) => boolean | PolicyCheckResult | Promise<boolean | PolicyCheckResult>;
}

export interface KillSwitchConfig {
  statusCodes?: number[];
  errorPatterns?: Array<string | RegExp>;
  tripOnSpendCeiling?: boolean;
}

export interface WriteGuardOptions {
  stateDir?: string;
  defaultTtlMs?: number | string;
  caps?: Record<string, number>;
  maxDailySpend?: number | null;
  timeZone?: string;
  killSwitch?: KillSwitchConfig;
  requireAttestation?: boolean;
  requireIdentity?: boolean;
  policyRules?: PolicyRule[];
  clock?: () => Date;
}

export interface AttestationRecord {
  version: number;
  attestationId: string;
  action: string;
  target: string;
  fingerprint: string;
  normalizedPayload: unknown;
  actor: string;
  ttlMs: number;
  createdAt: string;
  expiresAt: string;
  metadata: Record<string, unknown>;
}

export interface LockRecord {
  version: number;
  actionKey: string;
  state: LockState;
  action: string;
  target: string;
  fingerprint: string;
  attestationId: string | null;
  pid: number;
  host: string;
  startedAt: string;
  updatedAt: string;
  committedAt?: string | null;
  verifiedAt?: string | null;
  reconciled?: boolean;
  reconciledAt?: string;
  reconciledBy?: string;
  unknownReason?: string;
  unknownSignal?: string | null;
  verificationEvidence?: unknown;
  result?: unknown;
  metadata: Record<string, unknown>;
  history: Array<Record<string, unknown>>;
}

export type ReadbackVerifier = (args: {
  record: LockRecord;
  context?: unknown;
}) =>
  | boolean
  | { verified: boolean; evidence?: unknown; reason?: string }
  | Promise<boolean | { verified: boolean; evidence?: unknown; reason?: string }>;

export type ReconcileVerifier =
  | ((args: { record: LockRecord }) =>
      | { applied: boolean; evidence: unknown }
      | Promise<{ applied: boolean; evidence: unknown }>)
  | { applied: boolean; evidence: string };

export declare class WriteGuard {
  stateDir: string;
  defaultTtlMs: number;
  caps: Record<string, number>;
  maxDailySpend: number | null;
  timeZone?: string;
  requireAttestation: boolean;
  requireIdentity: boolean;
  policyEngine: PolicyEngine;

  constructor(options?: WriteGuardOptions);
  static load(stateDir?: string, overrides?: Partial<WriteGuardOptions>): Promise<WriteGuard>;

  init(overrides?: Partial<WriteGuardOptions>): Promise<Record<string, unknown>>;
  addPolicyRule(rule: PolicyRule): this;
  evaluatePolicies(ctx: PolicyContext): Promise<{ allowed: boolean; violations: Array<{ rule: string; reason: string; path: string }> }>;

  bindIdentity(options: { identity: string | Record<string, unknown>; label?: string; force?: boolean }): Promise<{
    bound: boolean;
    label: string;
    boundAt: string;
    hashPrefix: string;
  }>;
  assertIdentity(candidateIdentity: string | Record<string, unknown>): Promise<{
    verified: boolean;
    label: string;
    hashPrefix: string;
  }>;

  attest(options: {
    action: string;
    target: string;
    payload?: unknown;
    ttlMs?: number | string;
    actor?: string;
    metadata?: Record<string, unknown>;
  }): Promise<AttestationRecord>;
  verifyAttestation(options: {
    attestationId: string;
    action: string;
    target: string;
    payload?: unknown;
  }): Promise<{ verified: true; attestationId: string; fingerprint: string; expiresAt: string; record: AttestationRecord }>;

  isStopped(): Promise<boolean>;
  getKillSwitch(): Promise<Record<string, unknown> | null>;
  tripKillSwitch(options?: {
    reason?: string;
    signal?: string;
    actionKey?: string | null;
    metadata?: Record<string, unknown>;
  }): Promise<Record<string, unknown>>;
  clearKillSwitch(options?: { operator?: string; reason?: string }): Promise<Record<string, unknown>>;

  checkCap(options: { action: string; amount?: number }): Promise<Record<string, unknown>>;
  getCaps(): Promise<Record<string, unknown>>;

  beginWrite(options: {
    actionKey?: string;
    action: string;
    target: string;
    payload?: unknown;
    attestationId?: string | null;
    identity?: string | Record<string, unknown>;
    amount?: number;
    requireAttestation?: boolean;
    allowReconciledRetry?: boolean;
    metadata?: Record<string, unknown>;
  }): Promise<LockRecord>;
  commitWrite(
    actionKey: string,
    options?: { result?: unknown; verification?: { verified: boolean; evidence?: unknown } },
  ): Promise<LockRecord>;
  markUnknown(actionKey: string, options?: { error?: unknown; reason?: string; signal?: string }): Promise<LockRecord>;
  verifyReadback(actionKey: string, verifierFn: ReadbackVerifier, options?: { context?: unknown }): Promise<LockRecord>;
  reconcile(actionKey: string, verifierOrDecision: ReconcileVerifier, options?: { operator?: string }): Promise<LockRecord>;

  guardWrite<T = unknown>(options: {
    actionKey?: string;
    action: string;
    target: string;
    payload?: unknown;
    attestationId?: string | null;
    identity?: string | Record<string, unknown>;
    amount?: number;
    requireAttestation?: boolean;
    allowReconciledRetry?: boolean;
    unsafeSkipReadback?: boolean;
    metadata?: Record<string, unknown>;
    execute: (ctx: { lock: LockRecord; action: string; target: string; payload: unknown }) => Promise<T> | T;
    verifyReadback?: ReadbackVerifier;
  }): Promise<{ record: LockRecord; result: T }>;

  status(actionKey?: string): Promise<Record<string, unknown>>;
}

export declare class PolicyEngine {
  rules: PolicyRule[];
  constructor(initialRules?: PolicyRule[]);
  addPolicyRule(rule: PolicyRule): this;
  evaluate(ctx: PolicyContext): Promise<{ allowed: boolean; violations: Array<{ rule: string; reason: string; path: string }> }>;
}

export declare function spendCeilingRule(options: {
  maxAmount: number;
  field?: string;
  currency?: string;
  name?: string;
}): PolicyRule;

export declare function forbiddenTermsRule(options: {
  patterns: Array<string | RegExp>;
  fields?: string[];
  caseInsensitive?: boolean;
  name?: string;
}): PolicyRule;

export declare function piiLeakGuardRule(options?: {
  blockEmail?: boolean;
  blockPhone?: boolean;
  blockSsn?: boolean;
  blockCreditCard?: boolean;
  blockSecrets?: boolean;
  allowFields?: string[];
  name?: string;
}): PolicyRule;

export declare function customRule(rule: PolicyRule): PolicyRule;

export declare function normalizeValue(value: unknown): unknown;
export declare function canonicalize(value: unknown): string;
export declare function computeFingerprint(input: { action: string; target: string; payload?: unknown }): string;
export declare function deriveActionKey(input: {
  actionKey?: string;
  action: string;
  target: string;
  fingerprint?: string;
}): string;
export declare function diffPayloadSummary(
  expected: unknown,
  actual: unknown,
  prefix?: string,
): Array<{ path: string; kind: 'added' | 'removed' | 'changed' }>;

export declare function attest(
  stateDir: string,
  options: {
    action: string;
    target: string;
    payload?: unknown;
    ttlMs?: number | string;
    actor?: string;
    metadata?: Record<string, unknown>;
    now?: Date;
  },
): Promise<AttestationRecord>;
export declare function verifyAttestation(
  stateDir: string,
  options: { attestationId: string; action: string; target: string; payload?: unknown; now?: Date },
): Promise<{ verified: true; attestationId: string; fingerprint: string; expiresAt: string; record: AttestationRecord }>;
export declare function beginWrite(stateDir: string, options: Record<string, unknown>): Promise<LockRecord>;
export declare function commitWrite(stateDir: string, actionKey: string, options?: Record<string, unknown>): Promise<LockRecord>;
export declare function markUnknown(stateDir: string, actionKey: string, options?: Record<string, unknown>): Promise<LockRecord>;
export declare function verifyReadback(
  stateDir: string,
  actionKey: string,
  verifierFn: ReadbackVerifier,
  options?: { context?: unknown; now?: Date },
): Promise<LockRecord>;
export declare function reconcile(
  stateDir: string,
  actionKey: string,
  verifierOrDecision: ReconcileVerifier,
  options?: { operator?: string; now?: Date },
): Promise<LockRecord>;
export declare function getLockRecord(stateDir: string, actionKey: string): Promise<LockRecord | null>;
export declare function listLockRecords(stateDir: string): Promise<LockRecord[]>;
export declare function checkCap(stateDir: string, options: Record<string, unknown>): Promise<Record<string, unknown>>;
export declare function consumeCap(stateDir: string, options: Record<string, unknown>): Promise<Record<string, unknown>>;
export declare function getCapsStatus(stateDir: string, options?: Record<string, unknown>): Promise<Record<string, unknown>>;
export declare function isStopped(stateDir: string): Promise<boolean>;
export declare function getKillSwitch(stateDir: string): Promise<Record<string, unknown> | null>;
export declare function tripKillSwitch(stateDir: string, options?: Record<string, unknown>): Promise<Record<string, unknown>>;
export declare function clearKillSwitch(stateDir: string, options?: Record<string, unknown>): Promise<Record<string, unknown>>;
export declare function shouldTripOnError(
  error: unknown,
  config?: KillSwitchConfig,
): { shouldTrip: boolean; signal?: string; reason?: string };
export declare function bindIdentity(stateDir: string, options: Record<string, unknown>): Promise<Record<string, unknown>>;
export declare function assertIdentity(
  stateDir: string,
  candidateIdentity: string | Record<string, unknown>,
  options?: { now?: Date },
): Promise<Record<string, unknown>>;
export declare function getIdentityStatus(stateDir: string): Promise<Record<string, unknown>>;
export declare function parseDurationMs(input: number | string): number;
export declare function getLocalDayKey(date?: Date | number | string, timeZone?: string): string;
