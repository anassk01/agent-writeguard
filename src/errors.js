export const ERROR_CODES = Object.freeze({
  ERR_KILL_SWITCH_ACTIVE: 'ERR_KILL_SWITCH_ACTIVE',
  ERR_IDENTITY_NOT_BOUND: 'ERR_IDENTITY_NOT_BOUND',
  ERR_IDENTITY_MISMATCH: 'ERR_IDENTITY_MISMATCH',
  ERR_POLICY_VIOLATION: 'ERR_POLICY_VIOLATION',
  ERR_ATTESTATION_MISSING: 'ERR_ATTESTATION_MISSING',
  ERR_ATTESTATION_EXPIRED: 'ERR_ATTESTATION_EXPIRED',
  ERR_ATTESTATION_DRIFT: 'ERR_ATTESTATION_DRIFT',
  ERR_DAILY_CAP_EXCEEDED: 'ERR_DAILY_CAP_EXCEEDED',
  ERR_SPEND_CEILING_EXCEEDED: 'ERR_SPEND_CEILING_EXCEEDED',
  ERR_WRITE_IN_FLIGHT: 'ERR_WRITE_IN_FLIGHT',
  ERR_OUTCOME_UNKNOWN: 'ERR_OUTCOME_UNKNOWN',
  ERR_ALREADY_COMMITTED: 'ERR_ALREADY_COMMITTED',
  ERR_RECORD_NOT_FOUND: 'ERR_RECORD_NOT_FOUND',
  ERR_INVALID_STATE_TRANSITION: 'ERR_INVALID_STATE_TRANSITION',
  ERR_READBACK_REQUIRED: 'ERR_READBACK_REQUIRED',
  ERR_READBACK_FAILED: 'ERR_READBACK_FAILED',
  ERR_EXECUTION_FAILED: 'ERR_EXECUTION_FAILED',
  ERR_INVALID_ARGUMENT: 'ERR_INVALID_ARGUMENT',
});

export class WriteGuardError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {object} [options]
   * @param {object} [options.details]
   * @param {boolean} [options.retryable]
   * @param {boolean} [options.outcomeUnknown]
   * @param {unknown} [options.cause]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WriteGuardError';
    this.code = code;
    this.details = options.details ?? {};
    this.retryable = Boolean(options.retryable ?? false);
    this.outcomeUnknown = Boolean(options.outcomeUnknown ?? false);
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      outcomeUnknown: this.outcomeUnknown,
      details: this.details,
    };
  }
}

export function isWriteGuardError(err) {
  return err instanceof WriteGuardError || (Boolean(err) && err?.name === 'WriteGuardError' && typeof err?.code === 'string');
}
