import { ERROR_CODES, WriteGuardError } from './errors.js';

function getPathValue(obj, dotPath) {
  if (!obj || typeof obj !== 'object') return undefined;
  const parts = String(dotPath).split('.');
  let current = obj;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function walkStrings(value, prefix = '', visit) {
  if (value === null || value === undefined) return;
  if (typeof value === 'string') {
    visit(prefix || '$', value);
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      walkStrings(value[i], `${prefix}[${i}]`, visit);
    }
    return;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      const next = prefix ? `${prefix}.${k}` : k;
      walkStrings(v, next, visit);
    }
  }
}

function luhnCheck(digits) {
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function containsCreditCard(text) {
  const candidates = text.match(/(?:\d[ -]*?){13,19}/g);
  if (!candidates) return false;
  for (const candidate of candidates) {
    const digits = candidate.replace(/\D/g, '');
    if (digits.length >= 13 && digits.length <= 19 && luhnCheck(digits)) {
      return true;
    }
  }
  return false;
}

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/;
const PHONE_RE = /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/;
const SECRET_RE = /\b(?:sk_live_[a-zA-Z0-9]{16,}|pk_live_[a-zA-Z0-9]{16,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9-]{10,}|Bearer\s+[A-Za-z0-9\-._~+/]+=*)\b/;

/**
 * Policy rule enforcing a per-action spend ceiling.
 *
 * @param {{ maxAmount: number, field?: string, currency?: string, name?: string }} options
 */
export function spendCeilingRule({ maxAmount, field = 'amount', currency, name = 'spend-ceiling' } = {}) {
  if (typeof maxAmount !== 'number' || !Number.isFinite(maxAmount) || maxAmount < 0) {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'spendCeilingRule requires a finite non-negative maxAmount.');
  }
  return {
    name,
    check(ctx) {
      const payloadValue = getPathValue(ctx.payload, field);
      const hasExplicitAmount = typeof ctx.amount === 'number' && ctx.amount !== 0;
      const candidate = payloadValue !== undefined && payloadValue !== null
        ? (hasExplicitAmount ? Math.max(ctx.amount, Number(payloadValue)) : payloadValue)
        : (typeof ctx.amount === 'number' ? ctx.amount : undefined);
      if (candidate === undefined || candidate === null) {
        return { allowed: true };
      }
      const numeric = Number(candidate);
      if (!Number.isFinite(numeric)) {
        return {
          allowed: false,
          reason: `Non-numeric spend value at "${field}".`,
          path: field,
        };
      }
      if (currency && ctx.payload && typeof ctx.payload === 'object') {
        const payloadCurrency = getPathValue(ctx.payload, 'currency');
        if (payloadCurrency && String(payloadCurrency).toUpperCase() !== String(currency).toUpperCase()) {
          return { allowed: true };
        }
      }
      if (numeric > maxAmount) {
        return {
          allowed: false,
          reason: `Amount ${numeric} exceeds policy spend ceiling of ${maxAmount}${currency ? ` ${currency}` : ''}.`,
          path: field,
        };
      }
      return { allowed: true };
    },
  };
}

/**
 * Policy rule blocking forbidden terms or regex patterns in target or payload fields.
 *
 * @param {{ patterns: Array<string | RegExp>, fields?: string[], caseInsensitive?: boolean, name?: string }} options
 */
export function forbiddenTermsRule({ patterns = [], fields, caseInsensitive = true, name = 'forbidden-terms' } = {}) {
  const compiled = patterns.map((p) => {
    if (p instanceof RegExp) return p;
    const escaped = String(p).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(escaped, caseInsensitive ? 'i' : '');
  });

  return {
    name,
    check(ctx) {
      const checks = [];
      if (!fields || fields.length === 0) {
        if (typeof ctx.target === 'string') checks.push(['target', ctx.target]);
        walkStrings(ctx.payload, 'payload', (p, s) => checks.push([p, s]));
      } else {
        for (const f of fields) {
          const val = f === 'target' ? ctx.target : getPathValue(ctx.payload, f);
          walkStrings(val, f, (p, s) => checks.push([p, s]));
        }
      }

      for (const [path, text] of checks) {
        for (const re of compiled) {
          if (re.test(text)) {
            return {
              allowed: false,
              reason: `Forbidden term matched pattern ${re.toString()} at "${path}".`,
              path,
            };
          }
        }
      }
      return { allowed: true };
    },
  };
}

/**
 * Built-in PII & secret leak guard scanning payload strings.
 *
 * @param {{ blockEmail?: boolean, blockPhone?: boolean, blockSsn?: boolean, blockCreditCard?: boolean, blockSecrets?: boolean, allowFields?: string[], name?: string }} [options]
 */
export function piiLeakGuardRule({
  blockEmail = true,
  blockPhone = true,
  blockSsn = true,
  blockCreditCard = true,
  blockSecrets = true,
  allowFields = [],
  name = 'pii-leak-guard',
} = {}) {
  const allowedSet = new Set(allowFields.map((f) => String(f)));

  function isFieldAllowed(path) {
    if (allowedSet.has(path)) return true;
    const stripped = path.replace(/^payload\./, '');
    if (allowedSet.has(stripped)) return true;
    const leaf = stripped.split('.').pop();
    if (leaf && allowedSet.has(leaf)) return true;
    return false;
  }

  return {
    name,
    check(ctx) {
      const violations = [];
      walkStrings(ctx.payload, 'payload', (path, text) => {
        if (isFieldAllowed(path)) return;
        if (blockSecrets && SECRET_RE.test(text)) {
          violations.push({ path, reason: `Potential API key or bearer secret detected at "${path}".` });
        }
        if (blockCreditCard && containsCreditCard(text)) {
          violations.push({ path, reason: `Potential payment card number detected at "${path}".` });
        }
        if (blockSsn && SSN_RE.test(text)) {
          violations.push({ path, reason: `Potential SSN detected at "${path}".` });
        }
        if (blockEmail && EMAIL_RE.test(text)) {
          violations.push({ path, reason: `Email address PII detected at "${path}".` });
        }
        if (blockPhone && PHONE_RE.test(text)) {
          violations.push({ path, reason: `Phone number PII detected at "${path}".` });
        }
      });

      if (violations.length > 0) {
        return {
          allowed: false,
          reason: violations[0].reason,
          path: violations[0].path,
          violations,
        };
      }
      return { allowed: true };
    },
  };
}

/**
 * Creates a custom synchronous or asynchronous policy rule.
 *
 * @param {{ name: string, check: (ctx: object) => boolean | { allowed: boolean, reason?: string, path?: string } | Promise<any> }} rule
 */
export function customRule({ name, check }) {
  if (typeof name !== 'string' || !name.trim()) {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, 'Policy rule requires a non-empty name.');
  }
  if (typeof check !== 'function') {
    throw new WriteGuardError(ERROR_CODES.ERR_INVALID_ARGUMENT, `Policy rule "${name}" requires a check function.`);
  }
  return { name: name.trim(), check };
}

export class PolicyEngine {
  constructor(initialRules = []) {
    this.rules = [];
    for (const rule of initialRules) {
      this.addPolicyRule(rule);
    }
  }

  addPolicyRule(rule) {
    if (!rule || typeof rule.check !== 'function' || typeof rule.name !== 'string') {
      throw new WriteGuardError(
        ERROR_CODES.ERR_INVALID_ARGUMENT,
        'addPolicyRule expects an object with { name: string, check: Function }.',
      );
    }
    this.rules.push(rule);
    return this;
  }

  async evaluate(ctx) {
    const violations = [];
    for (const rule of this.rules) {
      const outcome = await rule.check(ctx);
      if (outcome === false) {
        violations.push({
          rule: rule.name,
          reason: `Blocked by policy rule "${rule.name}".`,
          path: '$',
        });
      } else if (outcome && typeof outcome === 'object' && outcome.allowed === false) {
        if (Array.isArray(outcome.violations) && outcome.violations.length > 0) {
          for (const v of outcome.violations) {
            violations.push({
              rule: rule.name,
              reason: v.reason || outcome.reason || `Blocked by policy rule "${rule.name}".`,
              path: v.path || outcome.path || '$',
            });
          }
        } else {
          violations.push({
            rule: rule.name,
            reason: outcome.reason || `Blocked by policy rule "${rule.name}".`,
            path: outcome.path || '$',
          });
        }
      }
    }
    return {
      allowed: violations.length === 0,
      violations,
    };
  }
}
