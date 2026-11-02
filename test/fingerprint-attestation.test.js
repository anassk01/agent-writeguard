import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  ERROR_CODES,
  WriteGuard,
  canonicalize,
  computeFingerprint,
  deriveActionKey,
  diffPayloadSummary,
} from '../src/index.js';

describe('Canonical Fingerprinting & Dry-Run Attestation', () => {
  let stateDir;

  beforeEach(async () => {
    stateDir = await mkdtemp(join(tmpdir(), 'wg-test-att-'));
  });

  afterEach(async () => {
    await rm(stateDir, { recursive: true, force: true });
  });

  it('produces identical SHA-256 fingerprints regardless of object key order or undefined keys', () => {
    const fp1 = computeFingerprint({
      action: 'stripe.payout',
      target: 'stripe:payouts',
      payload: { b: 2, a: 1, nested: { z: true, y: 'ok', ignored: undefined } },
    });
    const fp2 = computeFingerprint({
      action: 'stripe.payout',
      target: 'stripe:payouts',
      payload: { a: 1, b: 2, nested: { y: 'ok', z: true } },
    });
    assert.equal(fp1, fp2);
    assert.match(fp1, /^sha256:[a-f0-9]{64}$/);
  });

  it('rejects circular references and non-finite numbers cleanly', () => {
    const cyclic = { a: 1 };
    cyclic.self = cyclic;
    assert.throws(() => canonicalize(cyclic), (err) => err.code === ERROR_CODES.ERR_INVALID_ARGUMENT);
    assert.throws(() => canonicalize({ amount: Number.NaN }), (err) => err.code === ERROR_CODES.ERR_INVALID_ARGUMENT);
  });

  it('sanitizes actionKey against path traversal attempts', () => {
    const key = deriveActionKey({ actionKey: '../../etc/passwd', action: 'deploy', target: 'prod' });
    assert.ok(!key.includes('..'));
    assert.ok(!key.includes('/'));
  });

  it('verifies a valid dry-run attestation within TTL', async () => {
    const now = new Date('2026-06-01T10:00:00.000Z');
    const guard = new WriteGuard({ stateDir, clock: () => now });
    await guard.init();

    const att = await guard.attest({
      action: 'billing.charge',
      target: 'stripe:cus_123',
      payload: { amount: 499, currency: 'USD' },
      ttlMs: '24h',
    });

    const verified = await guard.verifyAttestation({
      attestationId: att.attestationId,
      action: 'billing.charge',
      target: 'stripe:cus_123',
      payload: { currency: 'USD', amount: 499 }, // different key order, same canonical fingerprint
    });

    assert.equal(verified.verified, true);
    assert.equal(verified.fingerprint, att.fingerprint);
  });

  it('refuses execution when payload drifts and reports changed fields', async () => {
    const guard = new WriteGuard({ stateDir });
    await guard.init();

    const att = await guard.attest({
      action: 'stripe.payout',
      target: 'stripe:payouts',
      payload: { amount: 100, recipient: 'acct_1', meta: { invoice: 'inv_1' } },
    });

    await assert.rejects(
      () =>
        guard.verifyAttestation({
          attestationId: att.attestationId,
          action: 'stripe.payout',
          target: 'stripe:payouts',
          payload: { amount: 1000, recipient: 'acct_1', meta: { invoice: 'inv_1' }, extra: true },
        }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.ERR_ATTESTATION_DRIFT);
        assert.ok(Array.isArray(err.details.payloadDiff));
        const paths = err.details.payloadDiff.map((d) => d.path);
        assert.ok(paths.includes('amount'));
        assert.ok(paths.includes('extra'));
        return true;
      },
    );
  });

  it('refuses execution when target drifts from attestation', async () => {
    const guard = new WriteGuard({ stateDir });
    await guard.init();

    const att = await guard.attest({
      action: 'pr.deploy',
      target: 'env:staging',
      payload: { sha: 'abc123' },
    });

    await assert.rejects(
      () =>
        guard.verifyAttestation({
          attestationId: att.attestationId,
          action: 'pr.deploy',
          target: 'env:production',
          payload: { sha: 'abc123' },
        }),
      (err) => err.code === ERROR_CODES.ERR_ATTESTATION_DRIFT && err.details.targetDrifted === true,
    );
  });

  it('refuses execution after attestation TTL expires', async () => {
    let currentTime = new Date('2026-06-01T10:00:00.000Z');
    const guard = new WriteGuard({ stateDir, clock: () => currentTime });
    await guard.init();

    const att = await guard.attest({
      action: 'crm.bulk_update',
      target: 'crm:deals',
      payload: { ids: [1, 2] },
      ttlMs: '1h',
    });

    // Advance 61 minutes
    currentTime = new Date('2026-06-01T11:01:00.000Z');

    await assert.rejects(
      () =>
        guard.verifyAttestation({
          attestationId: att.attestationId,
          action: 'crm.bulk_update',
          target: 'crm:deals',
          payload: { ids: [1, 2] },
        }),
      (err) => err.code === ERROR_CODES.ERR_ATTESTATION_EXPIRED,
    );
  });

  it('refuses execution when attestationId is missing or unknown', async () => {
    const guard = new WriteGuard({ stateDir });
    await guard.init();

    await assert.rejects(
      () =>
        guard.beginWrite({
          action: 'crm.update',
          target: 'crm:1',
          payload: { ok: true },
        }),
      (err) => err.code === ERROR_CODES.ERR_ATTESTATION_MISSING,
    );

    const diffs = diffPayloadSummary({ a: 1, b: 2 }, { a: 1, c: 3 });
    assert.deepEqual(diffs, [
      { path: 'b', kind: 'removed' },
      { path: 'c', kind: 'added' },
    ]);
  });
});
