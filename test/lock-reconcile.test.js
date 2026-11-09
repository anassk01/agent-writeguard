import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  ERROR_CODES,
  LOCK_STATES,
  WriteGuard,
  getLockRecord,
} from '../src/index.js';

describe('Atomic O_EXCL Lock, Read-Back Verification & Reconciliation', () => {
  let stateDir;

  beforeEach(async () => {
    stateDir = await mkdtemp(join(tmpdir(), 'wg-test-lock-'));
  });

  afterEach(async () => {
    await rm(stateDir, { recursive: true, force: true });
  });

  it('enforces OS-level O_EXCL exclusivity under 10 concurrent beginWrite calls', async () => {
    const guard = new WriteGuard({ stateDir, requireAttestation: false });
    await guard.init();

    const attempts = Array.from({ length: 10 }, () =>
      guard
        .beginWrite({
          actionKey: 'concurrent-payout-001',
          action: 'stripe.payout',
          target: 'stripe:payouts',
          payload: { amount: 500 },
        })
        .then(() => ({ ok: true }))
        .catch((err) => ({ ok: false, code: err.code })),
    );

    const results = await Promise.all(attempts);
    const winners = results.filter((r) => r.ok);
    const blocked = results.filter((r) => !r.ok);

    assert.equal(winners.length, 1, 'strictly one concurrent caller must acquire the O_EXCL lock');
    assert.equal(blocked.length, 9);
    for (const b of blocked) {
      assert.equal(b.code, ERROR_CODES.ERR_WRITE_IN_FLIGHT);
    }
  });

  it('transitions mid-flight timeout to outcome_unknown and hard-blocks blind retries', async () => {
    const guard = new WriteGuard({ stateDir });
    await guard.init();

    const payload = { invoiceId: 'inv_99', amount: 750 };
    const att = await guard.attest({
      action: 'stripe.payout',
      target: 'stripe:payouts',
      payload,
    });

    let sideEffectCalls = 0;

    await assert.rejects(
      () =>
        guard.guardWrite({
          actionKey: 'payout-inv-99',
          action: 'stripe.payout',
          target: 'stripe:payouts',
          payload,
          attestationId: att.attestationId,
          execute: async () => {
            sideEffectCalls += 1;
            throw new Error('ETIMEDOUT waiting for response');
          },
          verifyReadback: async () => ({ verified: true }),
        }),
      (err) => err.code === ERROR_CODES.ERR_EXECUTION_FAILED && err.outcomeUnknown === true,
    );

    const rec = await getLockRecord(stateDir, 'payout-inv-99');
    assert.equal(rec.state, LOCK_STATES.OUTCOME_UNKNOWN);

    // Blind retry MUST be hard-blocked before calling execute() again!
    await assert.rejects(
      () =>
        guard.guardWrite({
          actionKey: 'payout-inv-99',
          action: 'stripe.payout',
          target: 'stripe:payouts',
          payload,
          attestationId: att.attestationId,
          execute: async () => {
            sideEffectCalls += 1;
            return { ok: true };
          },
          verifyReadback: async () => ({ verified: true }),
        }),
      (err) => err.code === ERROR_CODES.ERR_OUTCOME_UNKNOWN && err.outcomeUnknown === true,
    );

    assert.equal(sideEffectCalls, 1, 'blind retry must NEVER invoke execute() a second time');
  });

  it('enforces mandatory verifyReadback hook and marks outcome_unknown if readback returns false', async () => {
    const guard = new WriteGuard({ stateDir, requireAttestation: false });
    await guard.init();

    // Missing verifyReadback is rejected upfront before executing side effect
    let ran = false;
    await assert.rejects(
      () =>
        guard.guardWrite({
          actionKey: 'missing-verifier',
          action: 'crm.update',
          target: 'crm:deals',
          payload: { id: 1 },
          execute: async () => {
            ran = true;
          },
        }),
      (err) => err.code === ERROR_CODES.ERR_READBACK_REQUIRED,
    );
    assert.equal(ran, false);

    // Failed read-back transitions lock to outcome_unknown
    await assert.rejects(
      () =>
        guard.guardWrite({
          actionKey: 'failed-readback',
          action: 'crm.update',
          target: 'crm:deals',
          payload: { id: 2 },
          execute: async () => ({ status: 200 }),
          verifyReadback: async () => ({ verified: false, reason: 'Deal row not updated in CRM' }),
        }),
      (err) => err.code === ERROR_CODES.ERR_READBACK_FAILED && err.outcomeUnknown === true,
    );

    const rec = await getLockRecord(stateDir, 'failed-readback');
    assert.equal(rec.state, LOCK_STATES.OUTCOME_UNKNOWN);
  });

  it('reconciles outcome_unknown as applied -> committed_verified and blocks duplicate execution', async () => {
    const guard = new WriteGuard({ stateDir, requireAttestation: false });
    await guard.init();

    await guard.beginWrite({
      actionKey: 'rec-applied-1',
      action: 'billing.refund',
      target: 'stripe:ch_55',
      payload: { amount: 200 },
    });
    await guard.markUnknown('rec-applied-1', { reason: 'Connection reset' });

    const reconciled = await guard.reconcile(
      'rec-applied-1',
      async () => ({ applied: true, evidence: { refundId: 're_12345' } }),
      { operator: 'ops-bot' },
    );

    assert.equal(reconciled.state, LOCK_STATES.COMMITTED_VERIFIED);
    assert.equal(reconciled.reconciled, true);
    assert.deepEqual(reconciled.verificationEvidence, { refundId: 're_12345' });

    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'rec-applied-1',
          action: 'billing.refund',
          target: 'stripe:ch_55',
          payload: { amount: 200 },
        }),
      (err) => err.code === ERROR_CODES.ERR_ALREADY_COMMITTED,
    );
  });

  it('reconciles outcome_unknown as not applied -> reconciled_aborted and permits explicit safe retry', async () => {
    const guard = new WriteGuard({ stateDir, requireAttestation: false });
    await guard.init();

    await guard.beginWrite({
      actionKey: 'rec-aborted-1',
      action: 'deploy.release',
      target: 'prod:api',
      payload: { tag: 'v1.2.3' },
    });
    await guard.markUnknown('rec-aborted-1', { reason: 'Worker OOM killed' });

    const aborted = await guard.reconcile(
      'rec-aborted-1',
      { applied: false, evidence: 'Release v1.2.3 absent in deployment registry' },
      { operator: 'sre-oncall' },
    );
    assert.equal(aborted.state, LOCK_STATES.RECONCILED_ABORTED);

    // Without allowReconciledRetry, retry is still blocked explicitly
    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'rec-aborted-1',
          action: 'deploy.release',
          target: 'prod:api',
          payload: { tag: 'v1.2.3' },
        }),
      (err) => err.code === ERROR_CODES.ERR_INVALID_STATE_TRANSITION,
    );

    // With allowReconciledRetry=true, old record is archived and retry succeeds end-to-end
    const retryRes = await guard.guardWrite({
      actionKey: 'rec-aborted-1',
      action: 'deploy.release',
      target: 'prod:api',
      payload: { tag: 'v1.2.3' },
      allowReconciledRetry: true,
      execute: async () => ({ deployed: true }),
      verifyReadback: async () => ({ verified: true, evidence: 'healthcheck=200' }),
    });
    assert.equal(retryRes.record.state, LOCK_STATES.COMMITTED_VERIFIED);
  });
});
