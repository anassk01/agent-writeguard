#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import {
  ERROR_CODES,
  WriteGuard,
  WriteGuardError,
  isWriteGuardError,
} from '../src/index.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

const BLOCKED_EXIT_CODES = new Set([
  ERROR_CODES.ERR_KILL_SWITCH_ACTIVE,
  ERROR_CODES.ERR_IDENTITY_NOT_BOUND,
  ERROR_CODES.ERR_IDENTITY_MISMATCH,
  ERROR_CODES.ERR_POLICY_VIOLATION,
  ERROR_CODES.ERR_ATTESTATION_MISSING,
  ERROR_CODES.ERR_ATTESTATION_EXPIRED,
  ERROR_CODES.ERR_ATTESTATION_DRIFT,
  ERROR_CODES.ERR_DAILY_CAP_EXCEEDED,
  ERROR_CODES.ERR_SPEND_CEILING_EXCEEDED,
  ERROR_CODES.ERR_WRITE_IN_FLIGHT,
  ERROR_CODES.ERR_ALREADY_COMMITTED,
  ERROR_CODES.ERR_READBACK_REQUIRED,
]);

function printHelp() {
  process.stdout.write(`agent-writeguard v${pkg.version} — Non-idempotent write safety harness for AI agents

Usage:
  writeguard <command> [options] [-- <command...>]

Commands:
  init        Initialize .writeguard state directory, caps, TTL, and optional identity
  attest      Create a SHA-256 fingerprint-bound dry-run attestation
  guard       Execute a non-idempotent command under O_EXCL lock + read-back verification
  reconcile   Resolve an outcome_unknown record via fresh read-back command or evidence
  status      Inspect kill switch, identity binding, daily caps, and lock records
  stop        Trip or clear the STOP kill switch
  caps        View or update per-action daily caps and spend ceiling
  identity    Bind, verify, or inspect salted tenant/account identity

Global Options:
  --dir <path>    State directory (default: WRITEGUARD_DIR or .writeguard)
  --json          Output structured JSON
  -h, --help      Show help
  -v, --version   Show version

Exit Codes:
  0  Success (action committed & verified, or query succeeded)
  1  Invalid arguments or unexpected error
  2  Blocked before side effect (attestation, cap, policy, identity, kill switch, duplicate lock)
  3  outcome_unknown — side effect may have applied; DO NOT blind-retry, run reconcile!
`);
}

function parseArgs(argv) {
  const separatorIdx = argv.indexOf('--');
  const ownArgs = separatorIdx === -1 ? argv : argv.slice(0, separatorIdx);
  const execArgs = separatorIdx === -1 ? [] : argv.slice(separatorIdx + 1);

  const flags = {};
  const multiFlags = {};
  const positionals = [];

  for (let i = 0; i < ownArgs.length; i += 1) {
    const token = ownArgs[i];
    if (token === '-h' || token === '--help') {
      flags.help = true;
    } else if (token === '-v' || token === '--version') {
      flags.version = true;
    } else if (token.startsWith('--')) {
      const eqIdx = token.indexOf('=');
      let key;
      let val;
      if (eqIdx !== -1) {
        key = token.slice(2, eqIdx);
        val = token.slice(eqIdx + 1);
      } else {
        key = token.slice(2);
        const next = ownArgs[i + 1];
        if (next !== undefined && !next.startsWith('--')) {
          val = next;
          i += 1;
        } else {
          val = true;
        }
      }
      if (key === 'cap' || key === 'set') {
        multiFlags[key] = multiFlags[key] || [];
        multiFlags[key].push(val);
      } else {
        flags[key] = val;
      }
    } else {
      positionals.push(token);
    }
  }

  return { command: positionals[0] || null, positionals: positionals.slice(1), flags, multiFlags, execArgs };
}

function parseCapPairs(pairs = []) {
  const caps = {};
  for (const raw of pairs) {
    if (typeof raw !== 'string' || !raw.includes('=')) {
      throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, `Invalid cap spec "${raw}". Use action=limit (e.g. stripe.payout=5).`);
    }
    const idx = raw.lastIndexOf('=');
    const name = raw.slice(0, idx).trim();
    const limit = Number(raw.slice(idx + 1).trim());
    if (!name || !Number.isInteger(limit) || limit < 0) {
      throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, `Invalid cap spec "${raw}". Limit must be a non-negative integer.`);
    }
    caps[name] = limit;
  }
  return caps;
}

async function loadPayload(flags) {
  if (flags['payload-file']) {
    const raw = await readFile(String(flags['payload-file']), 'utf8');
    return JSON.parse(raw);
  }
  if (flags.payload !== undefined && flags.payload !== true) {
    return JSON.parse(String(flags.payload));
  }
  return null;
}

function runSubprocess(command, args, { shell = false, env = {}, timeoutMs = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      shell,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let timer = null;

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
      }, timeoutMs);
    }

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      resolve({ code, signal, stdout: stdout.trim(), stderr: stderr.trim(), timedOut });
    });
  });
}

function output(data, asJson, humanFormatter) {
  if (asJson) {
    process.stdout.write(`${JSON.stringify(data, null, 2)}\n`);
  } else {
    process.stdout.write(`${humanFormatter(data)}\n`);
  }
}

async function main() {
  const { command, flags, multiFlags, execArgs } = parseArgs(process.argv.slice(2));
  const asJson = Boolean(flags.json);
  const stateDir = typeof flags.dir === 'string' ? flags.dir : (process.env.WRITEGUARD_DIR || '.writeguard');

  if (flags.version) {
    process.stdout.write(`${pkg.version}\n`);
    return;
  }
  if (flags.help || !command) {
    printHelp();
    return;
  }

  if (command === 'init') {
    const caps = parseCapPairs(multiFlags.cap || []);
    const maxDailySpend = flags['max-spend'] !== undefined ? Number(flags['max-spend']) : null;
    const defaultTtlMs = flags.ttl || '24h';
    const guard = new WriteGuard({
      stateDir,
      caps,
      maxDailySpend,
      defaultTtlMs,
      requireIdentity: Boolean(flags.identity),
    });
    const config = await guard.init();
    let identityInfo = null;
    if (typeof flags.identity === 'string') {
      identityInfo = await guard.bindIdentity({
        identity: flags.identity,
        label: typeof flags.label === 'string' ? flags.label : 'default',
        force: Boolean(flags.force),
      });
    }
    output({ initialized: true, stateDir: guard.stateDir, config, identity: identityInfo }, asJson, (d) => {
      const lines = [`Initialized WriteGuard at ${d.stateDir}`];
      if (Object.keys(d.config.caps).length > 0) {
        lines.push(`  caps: ${JSON.stringify(d.config.caps)}`);
      }
      if (d.config.maxDailySpend !== null) {
        lines.push(`  maxDailySpend: ${d.config.maxDailySpend}`);
      }
      if (d.identity) {
        lines.push(`  identity: bound (label=${d.identity.label}, hash=${d.identity.hashPrefix}...)`);
      }
      return lines.join('\n');
    });
    return;
  }

  const guard = await WriteGuard.load(stateDir);

  if (command === 'attest') {
    const action = flags.action;
    const target = flags.target;
    const payload = await loadPayload(flags);
    const rec = await guard.attest({
      action,
      target,
      payload,
      ttlMs: flags.ttl,
      actor: typeof flags.actor === 'string' ? flags.actor : 'cli',
    });
    output(rec, asJson, (r) =>
      [
        `Attestation created: ${r.attestationId}`,
        `  action:      ${r.action}`,
        `  target:      ${r.target}`,
        `  fingerprint: ${r.fingerprint}`,
        `  expiresAt:   ${r.expiresAt}`,
      ].join('\n'),
    );
    return;
  }

  if (command === 'guard') {
    if (execArgs.length === 0) {
      throw new WriteGuardError(
        ERROR_CODES.ERR_INVALID_ARGUMENT,
        'guard requires a command after "--". Example: writeguard guard --action ... --verify-cmd "..." -- node payout.mjs',
      );
    }
    const action = flags.action;
    const target = flags.target;
    const payload = await loadPayload(flags);
    const amount = flags.amount !== undefined ? Number(flags.amount) : 0;
    const verifyCmd = typeof flags['verify-cmd'] === 'string' ? flags['verify-cmd'] : null;
    const unsafeSkipReadback = Boolean(flags['unsafe-skip-readback']);
    const timeoutMs = flags.timeout ? Number(flags.timeout) : 0;

    if (!unsafeSkipReadback && !verifyCmd) {
      throw new WriteGuardError(
        ERROR_CODES.ERR_READBACK_REQUIRED,
        'guard requires --verify-cmd "<shell command>" for read-back verification (or pass --unsafe-skip-readback).',
      );
    }

    const result = await guard.guardWrite({
      actionKey: typeof flags.key === 'string' ? flags.key : undefined,
      action,
      target,
      payload,
      attestationId: typeof flags.attestation === 'string' ? flags.attestation : null,
      identity: typeof flags.identity === 'string' ? flags.identity : undefined,
      amount,
      requireAttestation: flags['no-attestation'] ? false : undefined,
      allowReconciledRetry: Boolean(flags['allow-reconciled-retry']),
      unsafeSkipReadback,
      execute: async ({ lock }) => {
        const res = await runSubprocess(execArgs[0], execArgs.slice(1), {
          timeoutMs,
          env: {
            WRITEGUARD_ACTION: lock.action,
            WRITEGUARD_TARGET: lock.target,
            WRITEGUARD_KEY: lock.actionKey,
            WRITEGUARD_FINGERPRINT: lock.fingerprint,
            WRITEGUARD_PAYLOAD: JSON.stringify(payload),
          },
        });
        if (res.timedOut) {
          const err = new Error(`Command timed out after ${timeoutMs}ms`);
          err.stdout = res.stdout;
          err.stderr = res.stderr;
          throw err;
        }
        if (res.code !== 0) {
          const err = new Error(`Command exited with status ${res.code}${res.stderr ? `: ${res.stderr}` : ''}`);
          err.stdout = res.stdout;
          err.stderr = res.stderr;
          throw err;
        }
        return { exitCode: res.code, stdout: res.stdout, stderr: res.stderr };
      },
      verifyReadback: verifyCmd
        ? async ({ record, context }) => {
            const verifyRes = await runSubprocess(verifyCmd, [], {
              shell: true,
              env: {
                WRITEGUARD_ACTION: record.action,
                WRITEGUARD_TARGET: record.target,
                WRITEGUARD_KEY: record.actionKey,
                WRITEGUARD_EXEC_STDOUT: context?.result?.stdout || '',
              },
            });
            if (verifyRes.code === 0) {
              return { verified: true, evidence: { stdout: verifyRes.stdout || 'exit 0' } };
            }
            return {
              verified: false,
              reason: `Read-back command exited with ${verifyRes.code}: ${verifyRes.stderr || verifyRes.stdout}`,
            };
          }
        : undefined,
    });

    output(result, asJson, (r) =>
      [
        `COMMITTED_VERIFIED: ${r.record.actionKey}`,
        `  action:   ${r.record.action}`,
        `  target:   ${r.record.target}`,
        `  verified: ${r.record.verifiedAt}`,
        r.result?.stdout ? `  stdout:   ${r.result.stdout}` : null,
      ]
        .filter(Boolean)
        .join('\n'),
    );
    return;
  }

  if (command === 'reconcile') {
    const actionKey = flags.key;
    const operator = typeof flags.operator === 'string' ? flags.operator : 'cli-operator';
    const verifyCmd = typeof flags['verify-cmd'] === 'string' ? flags['verify-cmd'] : null;

    let updated;
    if (verifyCmd) {
      updated = await guard.reconcile(
        actionKey,
        async ({ record }) => {
          const res = await runSubprocess(verifyCmd, [], {
            shell: true,
            env: {
              WRITEGUARD_ACTION: record.action,
              WRITEGUARD_TARGET: record.target,
              WRITEGUARD_KEY: record.actionKey,
            },
          });
          return {
            applied: res.code === 0,
            evidence: res.stdout || res.stderr || `verify-cmd exit=${res.code}`,
          };
        },
        { operator },
      );
    } else {
      const applied = Boolean(flags.applied);
      const notApplied = Boolean(flags['not-applied']);
      if (applied === notApplied) {
        throw new WriteGuardError(
          ERROR_CODES.ERR_INVALID_ARGUMENT,
          'reconcile requires exactly one of --applied, --not-applied, or --verify-cmd "<cmd>".',
        );
      }
      const evidence = typeof flags.evidence === 'string' ? flags.evidence : '';
      updated = await guard.reconcile(actionKey, { applied, evidence }, { operator });
    }

    output(updated, asJson, (r) =>
      [
        `Reconciled: ${r.actionKey}`,
        `  state:    ${r.state}`,
        `  operator: ${r.reconciledBy}`,
        `  evidence: ${typeof r.verificationEvidence === 'string' ? r.verificationEvidence : JSON.stringify(r.verificationEvidence)}`,
      ].join('\n'),
    );
    return;
  }

  throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, `Unknown command "${command}". Run "writeguard --help".`);
}

main().catch((err) => {
  const asJson = process.argv.includes('--json');
  let exitCode = 1;
  if (isWriteGuardError(err)) {
    if (err.outcomeUnknown || err.code === ERROR_CODES.ERR_OUTCOME_UNKNOWN || err.code === ERROR_CODES.ERR_READBACK_FAILED) {
      exitCode = 3;
    } else if (BLOCKED_EXIT_CODES.has(err.code)) {
      exitCode = 2;
    }
  }
  if (asJson) {
    process.stderr.write(`${JSON.stringify(isWriteGuardError(err) ? err.toJSON() : { message: err?.message || String(err) }, null, 2)}\n`);
  } else {
    const prefix = isWriteGuardError(err) ? `[${err.code}] ` : '[ERROR] ';
    process.stderr.write(`${prefix}${err?.message || String(err)}\n`);
  }
  process.exit(exitCode);
});
