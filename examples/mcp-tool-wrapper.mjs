/**
 * Drop-in Model Context Protocol (MCP) tool wrapper for mutating tools.
 * Forces dry-run attestation, policy/PII checks, daily caps, atomic O_EXCL locking,
 * and mandatory read-back verification before returning success to the LLM.
 *
 * Run:
 *   node examples/mcp-tool-wrapper.mjs
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  WriteGuard,
  forbiddenTermsRule,
  piiLeakGuardRule,
  spendCeilingRule,
} from '../src/index.js';

/**
 * Wraps any MCP tool handler so the agent follows a 2-phase protocol:
 *   - phase: "dry_run" -> returns attestationId + SHA-256 fingerprint (no side effect)
 *   - phase: "execute" -> verifies attestation + policies + O_EXCL lock + read-back
 */
export function wrapMcpTool(guard, { toolName, target, getAmount, execute, verifyReadback }) {
  return async function mcpToolHandler(args) {
    const { phase = 'dry_run', attestationId, actionKey, identity, ...payload } = args;

    if (phase === 'dry_run') {
      const att = await guard.attest({
        action: toolName,
        target,
        payload,
        actor: 'mcp-agent',
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'attested',
              attestationId: att.attestationId,
              fingerprint: att.fingerprint,
              expiresAt: att.expiresAt,
              nextStep: 'Review parameters, then call again with phase="execute" and this attestationId.',
            }),
          },
        ],
      };
    }

    const amount = typeof getAmount === 'function' ? getAmount(payload) : 0;
    const { record, result } = await guard.guardWrite({
      actionKey,
      action: toolName,
      target,
      payload,
      amount,
      attestationId,
      identity,
      execute: () => execute(payload),
      verifyReadback: ({ context }) => verifyReadback(payload, context?.result),
    });

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: record.state,
            actionKey: record.actionKey,
            verifiedAt: record.verifiedAt,
            result,
          }),
        },
      ],
    };
  };
}

async function demo() {
  const stateDir = await mkdtemp(join(tmpdir(), 'writeguard-mcp-demo-'));
  const crmStore = new Map();

  try {
    const guard = new WriteGuard({
      stateDir,
      caps: { 'crm.bulk_update': 3 },
      policyRules: [
        spendCeilingRule({ maxAmount: 1000, field: 'discountUsd' }),
        forbiddenTermsRule({ patterns: ['DROP TABLE', 'DELETE ALL'] }),
        piiLeakGuardRule({ blockEmail: true, blockSecrets: true }),
      ],
    });
    await guard.init();

    const bulkUpdateCrm = wrapMcpTool(guard, {
      toolName: 'crm.bulk_update',
      target: 'crm:deals',
      getAmount: (p) => Number(p.discountUsd || 0),
      execute: async (payload) => {
        crmStore.set(payload.batchId, { updated: payload.dealIds.length, stage: payload.stage });
        return { batchId: payload.batchId, updated: payload.dealIds.length };
      },
      verifyReadback: async (payload) => {
        const saved = crmStore.get(payload.batchId);
        return saved && saved.stage === payload.stage
          ? { verified: true, evidence: saved }
          : { verified: false, reason: 'CRM stage mismatch after update' };
      },
    });

    // Phase 1: Dry-run attestation
    const dryRes = await bulkUpdateCrm({
      phase: 'dry_run',
      batchId: 'batch-q4-01',
      dealIds: ['deal_101', 'deal_102'],
      stage: 'contract_sent',
      discountUsd: 250,
    });
    const dryData = JSON.parse(dryRes.content[0].text);
    console.log('[MCP dry_run]', dryData.attestationId);

    // Phase 2: Execute with drifted payload -> refused!
    try {
      await bulkUpdateCrm({
        phase: 'execute',
        attestationId: dryData.attestationId,
        actionKey: 'crm-batch-q4-01',
        batchId: 'batch-q4-01',
        dealIds: ['deal_101', 'deal_102', 'deal_999'], // drifted!
        stage: 'contract_sent',
        discountUsd: 250,
      });
    } catch (err) {
      console.log('[MCP drift blocked]', err.code);
    }

    // Phase 3: Execute with exact attested payload -> committed_verified!
    const execRes = await bulkUpdateCrm({
      phase: 'execute',
      attestationId: dryData.attestationId,
      actionKey: 'crm-batch-q4-01',
      batchId: 'batch-q4-01',
      dealIds: ['deal_101', 'deal_102'],
      stage: 'contract_sent',
      discountUsd: 250,
    });
    console.log('[MCP execute]', execRes.content[0].text);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  demo().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
