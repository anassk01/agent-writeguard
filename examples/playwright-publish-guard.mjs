/**
 * Browser / Playwright-style automation example:
 * Guarding SaaS catalog publishes with DOM read-back verification and
 * automatic STOP kill-switch tripping on HTTP 429 rate-limit signals.
 *
 * Run:
 *   node examples/playwright-publish-guard.mjs
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WriteGuard } from '../src/index.js';

// Simulated Playwright page + SaaS dashboard backend
function createMockBrowserSession() {
  const publishedSkus = new Map();
  let requests = 0;

  return {
    async clickPublish(sku, title, price) {
      requests += 1;
      if (requests === 2) {
        const err = new Error('Upstream SaaS API returned HTTP 429 Too Many Requests');
        err.status = 429;
        throw err;
      }
      publishedSkus.set(sku, { title, price, live: true });
      return { url: `https://app.example-saas.com/catalog/${sku}` };
    },
    async readDomCatalogEntry(sku) {
      return publishedSkus.get(sku) || null;
    },
  };
}

async function main() {
  const stateDir = await mkdtemp(join(tmpdir(), 'writeguard-browser-demo-'));
  const browser = createMockBrowserSession();

  try {
    const guard = new WriteGuard({
      stateDir,
      caps: { 'catalog.publish': 10 },
      killSwitch: { statusCodes: [429, 403], errorPatterns: [/rate.?limit/i] },
    });
    await guard.init();

    // Publish #1 succeeds and passes DOM read-back verification
    const sku1 = { sku: 'SKU-401', title: 'Pro Workflow Pack', price: 99 };
    const att1 = await guard.attest({ action: 'catalog.publish', target: 'saas:catalog', payload: sku1 });
    const res1 = await guard.guardWrite({
      actionKey: 'publish-SKU-401',
      action: 'catalog.publish',
      target: 'saas:catalog',
      payload: sku1,
      attestationId: att1.attestationId,
      execute: () => browser.clickPublish(sku1.sku, sku1.title, sku1.price),
      verifyReadback: async () => {
        const dom = await browser.readDomCatalogEntry(sku1.sku);
        return dom?.live && dom.price === sku1.price
          ? { verified: true, evidence: dom }
          : { verified: false, reason: 'Published SKU not visible in catalog DOM' };
      },
    });
    console.log('[1] SKU-401 state:', res1.record.state);

    // Publish #2 hits HTTP 429 -> automatically trips STOP kill switch!
    const sku2 = { sku: 'SKU-402', title: 'Enterprise Sync Pack', price: 249 };
    const att2 = await guard.attest({ action: 'catalog.publish', target: 'saas:catalog', payload: sku2 });
    try {
      await guard.guardWrite({
        actionKey: 'publish-SKU-402',
        action: 'catalog.publish',
        target: 'saas:catalog',
        payload: sku2,
        attestationId: att2.attestationId,
        execute: () => browser.clickPublish(sku2.sku, sku2.title, sku2.price),
        verifyReadback: async () => ({ verified: Boolean(await browser.readDomCatalogEntry(sku2.sku)) }),
      });
    } catch (err) {
      console.log('[2] SKU-402 failed & tripped STOP:', err.code, err.details);
    }

    // Publish #3 is blocked immediately before launching browser actions
    const sku3 = { sku: 'SKU-403', title: 'Audit Add-on', price: 49 };
    const att3 = await guard.attest({ action: 'catalog.publish', target: 'saas:catalog', payload: sku3 });
    try {
      await guard.guardWrite({
        actionKey: 'publish-SKU-403',
        action: 'catalog.publish',
        target: 'saas:catalog',
        payload: sku3,
        attestationId: att3.attestationId,
        execute: () => browser.clickPublish(sku3.sku, sku3.title, sku3.price),
        verifyReadback: async () => ({ verified: true }),
      });
    } catch (err) {
      console.log('[3] SKU-403 hard-stopped by kill switch:', err.code);
    }
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
