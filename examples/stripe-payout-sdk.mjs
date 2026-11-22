/**
 * End-to-end SDK example: Guarding a Stripe payout against a 30s timeout double-charge.
 *
 * Run:
 *   node examples/stripe-payout-sdk.mjs
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  WriteGuard,
  piiLeakGuardRule,
  spendCeilingRule,
} from '../src/index.js';

// Simulated external payment ledger (represents Stripe's remote state).
const remoteLedger = new Map();

async function fakeStripeCreatePayout(payoutId, payload, { simulateAmbiguousTimeout = false } = {}) {
  // Remote server actually processes the payout...
  remoteLedger.set(payoutId, { status: 'paid', ...payload, paidAt: new Date().toISOString() });

  if (simulateAmbiguousTimeout) {
    // ...but the TCP response drops after 30s! A naive retry loop would double-pay.
    throw new Error('ETIMEDOUT: socket hang up after 30000ms waiting for Stripe API');
  }
  return { id: payoutId, status: 'paid' };
}

async function main() {
  const stateDir = await mkdtemp(join(tmpdir(), 'writeguard-stripe-demo-'));
  try {
    const guard = new WriteGuard({
      stateDir,
      caps: { 'stripe.payout': 5 },
      maxDailySpend: 5000,
      requireIdentity: true,
      policyRules: [
        spendCeilingRule({ maxAmount: 2500, field: 'amount', currency: 'USD' }),
        piiLeakGuardRule({ allowFields: ['recipientAccount'] }),
      ],
    });

    await guard.init();
    await guard.bindIdentity({
      identity: 'acct_prod_acme_billing_01',
      label: 'stripe:acme-prod',
    });

    const payoutKey = 'payout-inv-2026-0042';
    const payload = {
      invoiceId: 'inv_2026_0042',
      recipientAccount: 'acct_vendor_8821',
      amount: 1250,
      currency: 'USD',
    };

    // 1. Dry-run attestation locks the exact payload + target fingerprint for 24h.
    const att = await guard.attest({
      action: 'stripe.payout',
      target: 'stripe:payouts',
      payload,
      ttlMs: '24h',
      actor: 'billing-agent',
    });
    console.log('[1] Attested payout:', att.attestationId, att.fingerprint.slice(0, 24) + '...');

    // 2. First attempt hits an ambiguous 30s timeout AFTER Stripe already committed.
    try {
      await guard.guardWrite({
        actionKey: payoutKey,
        action: 'stripe.payout',
        target: 'stripe:payouts',
        payload,
        amount: payload.amount,
        attestationId: att.attestationId,
        identity: 'acct_prod_acme_billing_01',
        execute: () => fakeStripeCreatePayout(payoutKey, payload, { simulateAmbiguousTimeout: true }),
        verifyReadback: async () => {
          const remote = remoteLedger.get(payoutKey);
          return remote ? { verified: true, evidence: remote } : { verified: false };
        },
      });
    } catch (err) {
      console.log(`[2] Ambiguous timeout caught -> ${err.code} (outcomeUnknown=${err.outcomeUnknown})`);
    }

    // 3. Rogue agent retries blindly -> HARD BLOCKED before touching Stripe again!
    try {
      await guard.guardWrite({
        actionKey: payoutKey,
        action: 'stripe.payout',
        target: 'stripe:payouts',
        payload,
        amount: payload.amount,
        attestationId: att.attestationId,
        identity: 'acct_prod_acme_billing_01',
        execute: () => fakeStripeCreatePayout(payoutKey, payload),
        verifyReadback: async () => ({ verified: true }),
      });
    } catch (err) {
      console.log(`[3] Blind retry BLOCKED -> ${err.code}: ${err.message}`);
    }

    // 4. Reconcile via fresh read-back against Stripe's ledger.
    const reconciled = await guard.reconcile(
      payoutKey,
      async () => {
        const remote = remoteLedger.get(payoutKey);
        return remote
          ? { applied: true, evidence: { remoteStatus: remote.status, paidAt: remote.paidAt } }
          : { applied: false, evidence: 'Not present in Stripe ledger' };
      },
      { operator: 'billing-reconciler' },
    );

    console.log(`[4] Reconciled state -> ${reconciled.state} (zero double-charges!)`);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
