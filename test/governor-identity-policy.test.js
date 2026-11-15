import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  ERROR_CODES,
  WriteGuard,
  customRule,
  forbiddenTermsRule,
  piiLeakGuardRule,
  spendCeilingRule,
} from '../src/index.js';

describe('Daily Cap Governor, STOP Kill Switch, Salted Identity & Policy/PII Gate', () => {
  let stateDir;

  beforeEach(async () => {
    stateDir = await mkdtemp(join(tmpdir(), 'wg-test-gov-'));
  });

  afterEach(async () => {
    await rm(stateDir, { recursive: true, force: true });
  });

  it('enforces per-action daily caps and automatically rolls over on the next local day', async () => {
    let now = new Date('2026-06-10T23:55:00.000Z');
    const guard = new WriteGuard({
      stateDir,
      timeZone: 'UTC',
      caps: { 'crm.bulk_update': 2 },
      requireAttestation: false,
      clock: () => now,
    });
    await guard.init();

    await guard.guardWrite({
      actionKey: 'job-1',
      action: 'crm.bulk_update',
      target: 'crm:deals',
      payload: { batch: 1 },
      execute: async () => 'ok',
      verifyReadback: async () => true,
    });
    await guard.guardWrite({
      actionKey: 'job-2',
      action: 'crm.bulk_update',
      target: 'crm:deals',
      payload: { batch: 2 },
      execute: async () => 'ok',
      verifyReadback: async () => true,
    });

    // 3rd call on same UTC day must be blocked
    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'job-3',
          action: 'crm.bulk_update',
          target: 'crm:deals',
          payload: { batch: 3 },
        }),
      (err) => err.code === ERROR_CODES.ERR_DAILY_CAP_EXCEEDED,
    );

    // Advance past midnight UTC -> automatic local-day rollover!
    now = new Date('2026-06-11T00:05:00.000Z');
    const capStatus = await guard.checkCap({ action: 'crm.bulk_update' });
    assert.equal(capStatus.allowed, true);
    assert.equal(capStatus.used, 0);
    assert.equal(capStatus.dayKey, '2026-06-11');

    const nextDay = await guard.guardWrite({
      actionKey: 'job-3-next-day',
      action: 'crm.bulk_update',
      target: 'crm:deals',
      payload: { batch: 3 },
      execute: async () => 'ok',
      verifyReadback: async () => true,
    });
    assert.equal(nextDay.record.state, 'committed_verified');
  });

  it('auto-trips STOP kill switch on HTTP 429 and blocks all subsequent writes until cleared', async () => {
    const guard = new WriteGuard({
      stateDir,
      requireAttestation: false,
      killSwitch: { statusCodes: [429], errorPatterns: [/rate.?limit/i] },
    });
    await guard.init();

    await assert.rejects(
      () =>
        guard.guardWrite({
          actionKey: 'api-call-1',
          action: 'saas.publish',
          target: 'saas:catalog',
          payload: { sku: 'A1' },
          execute: async () => {
            const err = new Error('Too Many Requests');
            err.status = 429;
            throw err;
          },
          verifyReadback: async () => true,
        }),
      (err) => err.code === ERROR_CODES.ERR_EXECUTION_FAILED && err.details.killSwitchTripped === true,
    );

    assert.equal(await guard.isStopped(), true);

    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'api-call-2',
          action: 'saas.publish',
          target: 'saas:catalog',
          payload: { sku: 'A2' },
        }),
      (err) => err.code === ERROR_CODES.ERR_KILL_SWITCH_ACTIVE,
    );

    await guard.clearKillSwitch({ operator: 'ops-lead', reason: 'Rate limit window reset' });
    assert.equal(await guard.isStopped(), false);

    const resumed = await guard.guardWrite({
      actionKey: 'api-call-2',
      action: 'saas.publish',
      target: 'saas:catalog',
      payload: { sku: 'A2' },
      execute: async () => ({ ok: true }),
      verifyReadback: async () => true,
    });
    assert.equal(resumed.record.state, 'committed_verified');
  });

  it('auto-trips STOP kill switch on daily spend ceiling breach when configured', async () => {
    const guard = new WriteGuard({
      stateDir,
      requireAttestation: false,
      maxDailySpend: 1000,
      killSwitch: { tripOnSpendCeiling: true },
    });
    await guard.init();

    await guard.guardWrite({
      actionKey: 'pay-1',
      action: 'stripe.payout',
      target: 'stripe:payouts',
      payload: { amount: 700 },
      amount: 700,
      execute: async () => 'paid',
      verifyReadback: async () => true,
    });

    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'pay-2',
          action: 'stripe.payout',
          target: 'stripe:payouts',
          payload: { amount: 400 },
          amount: 400,
        }),
      (err) => err.code === ERROR_CODES.ERR_SPEND_CEILING_EXCEEDED,
    );

    assert.equal(await guard.isStopped(), true);
  });

  it('binds salted identity without storing plaintext and blocks cross-tenant writes', async () => {
    const guard = new WriteGuard({
      stateDir,
      requireAttestation: false,
      requireIdentity: true,
    });
    await guard.init();

    const rawSecretIdentity = 'tenant_acme_prod_secret_9911';
    const bound = await guard.bindIdentity({
      identity: rawSecretIdentity,
      label: 'acme-prod',
    });
    assert.equal(bound.bound, true);

    // Ensure plaintext identity is NEVER stored on disk
    const rawFile = await readFile(join(stateDir, 'identity.json'), 'utf8');
    assert.ok(!rawFile.includes(rawSecretIdentity), 'identity.json must never contain plaintext identity');

    // Wrong tenant blocked
    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'tenant-check-1',
          action: 'billing.charge',
          target: 'stripe:cus_1',
          payload: { amount: 50 },
          identity: 'tenant_other_company_staging',
        }),
      (err) => err.code === ERROR_CODES.ERR_IDENTITY_MISMATCH,
    );

    // Right tenant passes
    const ok = await guard.guardWrite({
      actionKey: 'tenant-check-2',
      action: 'billing.charge',
      target: 'stripe:cus_1',
      payload: { amount: 50 },
      identity: rawSecretIdentity,
      execute: async () => ({ charged: true }),
      verifyReadback: async () => true,
    });
    assert.equal(ok.record.state, 'committed_verified');
  });

  it('blocks spend ceiling, forbidden terms, PII/secrets leaks, and custom async policies', async () => {
    const guard = new WriteGuard({
      stateDir,
      requireAttestation: false,
    });
    await guard.init();

    guard
      .addPolicyRule(spendCeilingRule({ maxAmount: 500, field: 'amount', currency: 'USD' }))
      .addPolicyRule(forbiddenTermsRule({ patterns: ['DROP TABLE', /force.?push/i] }))
      .addPolicyRule(piiLeakGuardRule({ allowFields: ['supportContact'] }))
      .addPolicyRule(
        customRule({
          name: 'business-hours-check',
          check: async (ctx) =>
            ctx.payload?.skipReview === true
              ? { allowed: false, reason: 'skipReview flag is prohibited' }
              : { allowed: true },
        }),
      );

    // 1. Spend ceiling violation
    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'pol-1',
          action: 'stripe.payout',
          target: 'stripe:payouts',
          payload: { amount: 900, currency: 'USD' },
        }),
      (err) => err.code === ERROR_CODES.ERR_POLICY_VIOLATION && err.details.violations[0].rule === 'spend-ceiling',
    );

    // 2. Forbidden terms violation
    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'pol-2',
          action: 'pr.deploy',
          target: 'repo:main',
          payload: { note: 'Run force-push to main' },
        }),
      (err) => err.code === ERROR_CODES.ERR_POLICY_VIOLATION && err.details.violations[0].rule === 'forbidden-terms',
    );

    // 3. PII leak (email + secret key)
    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'pol-3',
          action: 'crm.note',
          target: 'crm:public_feed',
          payload: { note: 'Contact jane.doe@acme.io with key sk_live_1234567890abcdef1234' },
        }),
      (err) => err.code === ERROR_CODES.ERR_POLICY_VIOLATION && err.details.violations[0].rule === 'pii-leak-guard',
    );

    // 4. Custom async rule violation
    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'pol-4',
          action: 'pr.deploy',
          target: 'repo:main',
          payload: { skipReview: true },
        }),
      (err) => err.code === ERROR_CODES.ERR_POLICY_VIOLATION && err.details.violations[0].rule === 'business-hours-check',
    );

    // 5. Clean payload with allowListed email field passes!
    const ok = await guard.guardWrite({
      actionKey: 'pol-5',
      action: 'stripe.payout',
      target: 'stripe:payouts',
      payload: { amount: 250, currency: 'USD', supportContact: 'billing@acme.io' },
      execute: async () => ({ paid: true }),
      verifyReadback: async () => true,
    });
    assert.equal(ok.record.state, 'committed_verified');
  });

  it('detects SSN, phone numbers, and Luhn-valid payment cards in PII leak guard', async () => {
    const guard = new WriteGuard({
      stateDir,
      requireAttestation: false,
      policyRules: [piiLeakGuardRule()],
    });
    await guard.init();

    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'pii-ssn',
          action: 'crm.note',
          target: 'crm:1',
          payload: { comment: 'Tax ID 123-45-6789' },
        }),
      (err) => err.code === ERROR_CODES.ERR_POLICY_VIOLATION,
    );

    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'pii-phone',
          action: 'crm.note',
          target: 'crm:2',
          payload: { comment: 'Call +1 415-555-0199 urgently' },
        }),
      (err) => err.code === ERROR_CODES.ERR_POLICY_VIOLATION,
    );

    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'pii-cc',
          action: 'crm.note',
          target: 'crm:3',
          payload: { comment: 'Card 4532 0151 1283 0366' },
        }),
      (err) => err.code === ERROR_CODES.ERR_POLICY_VIOLATION,
    );
  });

  it('supports wildcard (*) daily cap fallback and error-pattern kill-switch auto-trip', async () => {
    const guard = new WriteGuard({
      stateDir,
      requireAttestation: false,
      caps: { '*': 1 },
      killSwitch: { statusCodes: [429], errorPatterns: [/account.?suspended/i] },
    });
    await guard.init();

    await guard.guardWrite({
      actionKey: 'wild-1',
      action: 'any.custom.action',
      target: 'svc:1',
      payload: {},
      execute: async () => 'ok',
      verifyReadback: async () => true,
    });

    await assert.rejects(
      () =>
        guard.beginWrite({
          actionKey: 'wild-2',
          action: 'any.custom.action',
          target: 'svc:2',
          payload: {},
        }),
      (err) => err.code === ERROR_CODES.ERR_DAILY_CAP_EXCEEDED,
    );

    // Different action gets its own wildcard bucket of 1, hits error pattern -> trips STOP
    await assert.rejects(
      () =>
        guard.guardWrite({
          actionKey: 'wild-3',
          action: 'other.action',
          target: 'svc:3',
          payload: {},
          execute: async () => {
            throw new Error('Upstream error: account_suspended by billing gateway');
          },
          verifyReadback: async () => true,
        }),
      (err) => err.code === ERROR_CODES.ERR_EXECUTION_FAILED && err.details.killSwitchTripped === true,
    );
    assert.equal(await guard.isStopped(), true);
  });
});
