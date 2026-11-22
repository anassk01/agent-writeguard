import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, '../bin/writeguard.mjs');

function runCli(args, env = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => {
      stdout += d.toString('utf8');
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolvePromise({ code, stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

describe('writeguard CLI End-to-End', () => {
  let stateDir;

  beforeEach(async () => {
    stateDir = await mkdtemp(join(tmpdir(), 'wg-test-cli-'));
  });

  afterEach(async () => {
    await rm(stateDir, { recursive: true, force: true });
  });

  it('runs init -> attest -> guard (verified) -> duplicate block -> status', async () => {
    // 1. init with cap & identity
    const initRes = await runCli([
      'init',
      '--dir', stateDir,
      '--cap', 'deploy.release=2',
      '--identity', 'org:acme:prod',
      '--label', 'acme-prod',
      '--json',
    ]);
    assert.equal(initRes.code, 0, initRes.stderr);
    const initJson = JSON.parse(initRes.stdout);
    assert.equal(initJson.initialized, true);
    assert.equal(initJson.identity.bound, true);

    // 2. attest
    const payload = JSON.stringify({ service: 'billing', version: '1.4.0' });
    const attRes = await runCli([
      'attest',
      '--dir', stateDir,
      '--action', 'deploy.release',
      '--target', 'prod:us-east',
      '--payload', payload,
      '--ttl', '2h',
      '--json',
    ]);
    assert.equal(attRes.code, 0, attRes.stderr);
    const att = JSON.parse(attRes.stdout);
    assert.match(att.attestationId, /^att_/);

    // 3. guard with drifted payload -> exit code 2 (blocked)
    const driftRes = await runCli([
      'guard',
      '--dir', stateDir,
      '--key', 'rel-1.4.0',
      '--action', 'deploy.release',
      '--target', 'prod:us-east',
      '--attestation', att.attestationId,
      '--identity', 'org:acme:prod',
      '--payload', JSON.stringify({ service: 'billing', version: '9.9.9' }),
      '--verify-cmd', 'true',
      '--json',
      '--',
      'node', '-e', 'console.log("should not run")',
    ]);
    assert.equal(driftRes.code, 2);
    assert.equal(JSON.parse(driftRes.stderr).code, 'ERR_ATTESTATION_DRIFT');

    // 4. guard with exact payload + read-back verification -> exit code 0
    const markerFile = join(stateDir, 'deployed.marker');
    const guardRes = await runCli([
      'guard',
      '--dir', stateDir,
      '--key', 'rel-1.4.0',
      '--action', 'deploy.release',
      '--target', 'prod:us-east',
      '--attestation', att.attestationId,
      '--identity', 'org:acme:prod',
      '--payload', payload,
      '--verify-cmd', `test -f "${markerFile}"`,
      '--json',
      '--',
      'node', '-e', `require('fs').writeFileSync(${JSON.stringify(markerFile)}, 'ok'); console.log('done')`,
    ]);
    assert.equal(guardRes.code, 0, guardRes.stderr);
    const guardJson = JSON.parse(guardRes.stdout);
    assert.equal(guardJson.record.state, 'committed_verified');

    // 5. Duplicate run -> exit code 2 (ERR_ALREADY_COMMITTED)
    const dupRes = await runCli([
      'guard',
      '--dir', stateDir,
      '--key', 'rel-1.4.0',
      '--action', 'deploy.release',
      '--target', 'prod:us-east',
      '--attestation', att.attestationId,
      '--identity', 'org:acme:prod',
      '--payload', payload,
      '--verify-cmd', 'true',
      '--json',
      '--',
      'node', '-e', 'console.log("dup")',
    ]);
    assert.equal(dupRes.code, 2);
    assert.equal(JSON.parse(dupRes.stderr).code, 'ERR_ALREADY_COMMITTED');

    // 6. status
    const statusRes = await runCli(['status', '--dir', stateDir, '--json']);
    assert.equal(statusRes.code, 0);
    const statusJson = JSON.parse(statusRes.stdout);
    assert.equal(statusJson.summary.committed_verified, 1);
    assert.equal(statusJson.caps.actions['deploy.release'].used, 1);
  });

  it('exits with code 3 on ambiguous failure, blocks blind retry, and supports reconcile + stop + caps', async () => {
    await runCli(['init', '--dir', stateDir, '--cap', 'stripe.payout=5']);

    const payloadPath = join(stateDir, 'payout.json');
    await writeFile(payloadPath, JSON.stringify({ amount: 300, invoice: 'inv_7' }), 'utf8');

    const attRes = await runCli([
      'attest',
      '--dir', stateDir,
      '--action', 'stripe.payout',
      '--target', 'stripe:payouts',
      '--payload-file', payloadPath,
      '--json',
    ]);
    const att = JSON.parse(attRes.stdout);

    // Command fails mid-flight -> exit code 3 (outcome_unknown)
    const failRes = await runCli([
      'guard',
      '--dir', stateDir,
      '--key', 'pay-inv-7',
      '--action', 'stripe.payout',
      '--target', 'stripe:payouts',
      '--attestation', att.attestationId,
      '--payload-file', payloadPath,
      '--verify-cmd', 'true',
      '--json',
      '--',
      'node', '-e', 'console.error("ETIMEDOUT"); process.exit(1)',
    ]);
    assert.equal(failRes.code, 3);

    // Blind retry -> exit code 3 (ERR_OUTCOME_UNKNOWN)
    const retryRes = await runCli([
      'guard',
      '--dir', stateDir,
      '--key', 'pay-inv-7',
      '--action', 'stripe.payout',
      '--target', 'stripe:payouts',
      '--attestation', att.attestationId,
      '--payload-file', payloadPath,
      '--verify-cmd', 'true',
      '--json',
      '--',
      'node', '-e', 'console.log("retry")',
    ]);
    assert.equal(retryRes.code, 3);
    assert.equal(JSON.parse(retryRes.stderr).code, 'ERR_OUTCOME_UNKNOWN');

    // Reconcile as applied via CLI
    const recRes = await runCli([
      'reconcile',
      '--dir', stateDir,
      '--key', 'pay-inv-7',
      '--applied',
      '--evidence', 'Verified transfer tr_8821 in Stripe dashboard',
      '--operator', 'finance-ops',
      '--json',
    ]);
    assert.equal(recRes.code, 0, recRes.stderr);
    assert.equal(JSON.parse(recRes.stdout).state, 'committed_verified');

    // STOP kill switch trip & clear via CLI
    const stopRes = await runCli(['stop', '--dir', stateDir, '--reason', 'Maintenance freeze', '--json']);
    assert.equal(stopRes.code, 0);
    assert.equal(JSON.parse(stopRes.stdout).active, true);

    const blockedRes = await runCli([
      'guard',
      '--dir', stateDir,
      '--key', 'pay-inv-8',
      '--action', 'stripe.payout',
      '--target', 'stripe:payouts',
      '--no-attestation',
      '--verify-cmd', 'true',
      '--json',
      '--',
      'node', '-e', 'console.log("blocked")',
    ]);
    assert.equal(blockedRes.code, 2);
    assert.equal(JSON.parse(blockedRes.stderr).code, 'ERR_KILL_SWITCH_ACTIVE');

    const clearRes = await runCli(['stop', '--dir', stateDir, '--clear', '--operator', 'sre', '--json']);
    assert.equal(clearRes.code, 0);
    assert.equal(JSON.parse(clearRes.stdout).cleared, true);

    // Update caps via CLI
    const capsRes = await runCli(['caps', '--dir', stateDir, '--set', 'stripe.payout=12', '--max-spend', '2500', '--json']);
    assert.equal(capsRes.code, 0);
    const capsJson = JSON.parse(capsRes.stdout);
    assert.equal(capsJson.actions['stripe.payout'].limit, 12);
    assert.equal(capsJson.maxDailySpend, 2500);
  });

  it('supports identity bind/verify and reconcile --verify-cmd via CLI', async () => {
    await runCli(['init', '--dir', stateDir]);

    const bindRes = await runCli(['identity', '--dir', stateDir, '--bind', 'tenant:beta-prod', '--label', 'beta-prod', '--json']);
    assert.equal(bindRes.code, 0, bindRes.stderr);

    const okId = await runCli(['identity', '--dir', stateDir, '--verify', 'tenant:beta-prod', '--json']);
    assert.equal(okId.code, 0, okId.stderr);
    assert.equal(JSON.parse(okId.stdout).verified, true);

    const badId = await runCli(['identity', '--dir', stateDir, '--verify', 'tenant:wrong', '--json']);
    assert.equal(badId.code, 2);
    assert.equal(JSON.parse(badId.stderr).code, 'ERR_IDENTITY_MISMATCH');

    // Trigger outcome_unknown then reconcile with --verify-cmd returning exit 1 (not applied)
    const failRes = await runCli([
      'guard',
      '--dir', stateDir,
      '--key', 'cmd-rec-1',
      '--action', 'crm.sync',
      '--target', 'crm:accounts',
      '--no-attestation',
      '--identity', 'tenant:beta-prod',
      '--verify-cmd', 'true',
      '--json',
      '--',
      'node', '-e', 'process.exit(1)',
    ]);
    assert.equal(failRes.code, 3);

    const recCmdRes = await runCli([
      'reconcile',
      '--dir', stateDir,
      '--key', 'cmd-rec-1',
      '--verify-cmd', 'echo "not found in remote" && exit 1',
      '--operator', 'auto-reconciler',
      '--json',
    ]);
    assert.equal(recCmdRes.code, 0, recCmdRes.stderr);
    assert.equal(JSON.parse(recCmdRes.stdout).state, 'reconciled_aborted');
  });
});
