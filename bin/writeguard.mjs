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
