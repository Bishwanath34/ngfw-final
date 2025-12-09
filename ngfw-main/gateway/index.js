const express = require('express');
const axios = require('axios');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const pem = require('pem');
const https = require('https');

// ---------------- BASIC CONFIG ----------------

const PORT = process.env.PORT || 4001;
const BACKEND_URL = process.env.BACKEND_URL || 'https://localhost:9001';

const ML_SCORE_URL = process.env.ML_SCORE_URL || 'http://localhost:5000/score';
const ML_POLICY_URL =
  process.env.ML_POLICY_URL || 'http://localhost:5000/policy/recommend';

const SIGNATURES_PATH = path.join(__dirname, 'signatures.json');
const DB_DIR = path.join(__dirname, '..', 'db');
const CHAIN_FILE = path.join(DB_DIR, 'audit_chain.jsonl');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

let auditLogs = [];
const MAX_LOGS = 5000;

// DDoS / rate limiting (very simple window per IP)
const RATE_WINDOW_MS = 5000; // 5 second window
const RATE_LIMIT = 20;       // >20 reqs per window => DDoS risk
const rateTable = new Map(); // key: ip -> { windowStart, count }

// ---------------- SIGNATURE ENGINE ----------------

let signatureCache = {
  loadedAt: null,
  mtimeMs: 0,
  signatures: [],
};

function loadSignaturesFromDisk() {
  try {
    const stat = fs.statSync(SIGNATURES_PATH);
    if (signatureCache.mtimeMs === stat.mtimeMs && signatureCache.signatures.length) {
      return signatureCache.signatures;
    }
    const raw = fs.readFileSync(SIGNATURES_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    const sigs = Array.isArray(parsed.signatures) ? parsed.signatures : [];
    signatureCache = {
      loadedAt: new Date(),
      mtimeMs: stat.mtimeMs,
      signatures: sigs,
    };
    console.log('[NGFW] Loaded', sigs.length, 'signatures from', SIGNATURES_PATH);
    return sigs;
  } catch (err) {
    if (!signatureCache.signatures.length) {
      console.log('[NGFW] No signature file or invalid JSON; running with empty signatures:', err.message);
    }
    return signatureCache.signatures;
  }
}

function evaluateSignatures(ctx, req) {
  const sigs = loadSignaturesFromDisk();
  let risk = 0.0;
  const reasons = [];
  let hardBlock = false;

  for (const sig of sigs) {
    const id = sig.id || sig.name || 'sig';
    const roles = sig.roles;
    if (Array.isArray(roles) && roles.length && !roles.includes(ctx.role)) {
      continue;
    }

    let matched = false;

    if (sig.pathContains && ctx.path.includes(sig.pathContains)) {
      matched = true;
    }

    if (!matched && sig.pathRegex) {
      try {
        const re = new RegExp(sig.pathRegex, 'i');
        if (re.test(ctx.path)) matched = true;
      } catch {
        // ignore bad regex
      }
    }

    if (!matched && sig.userAgentContains) {
      const ua = (ctx.userAgent || '').toLowerCase();
      if (ua.includes(String(sig.userAgentContains).toLowerCase())) {
        matched = true;
      }
    }

    if (!matched && sig.headerName && sig.headerContains) {
      const headerVal = String(
        req.headers[String(sig.headerName).toLowerCase()] || ''
      ).toLowerCase();
      if (headerVal.includes(String(sig.headerContains).toLowerCase())) {
        matched = true;
      }
    }

    if (!matched) continue;

    const increment = typeof sig.risk === 'number' ? sig.risk : 0.3;
    risk += increment;
    reasons.push(`sig:${id}`);

    if (sig.action === 'block' || sig.action === 'hard_block') {
      hardBlock = true;
    }
  }

  if (risk > 1.0) risk = 1.0;

  return { risk, reasons, hardBlock };
}

// ---------------- TAMPER-EVIDENT CHAIN ----------------

let lastHash = null;
let lastIndex = -1;

function computeHash(block) {
  const clone = { ...block };
  delete clone.hash;
  const payload = JSON.stringify(clone);
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function bootstrapChain() {
  if (!fs.existsSync(CHAIN_FILE)) {
    lastHash = null;
    lastIndex = -1;
    return;
  }
  try {
    const content = fs.readFileSync(CHAIN_FILE, 'utf8').trim();
    if (!content) {
      lastHash = null;
      lastIndex = -1;
      return;
    }
    const lines = content.split('\n').filter(Boolean);
    const lastBlock = JSON.parse(lines[lines.length - 1]);
    lastHash = lastBlock.hash || null;
    if (typeof lastBlock.index === 'number') {
      lastIndex = lastBlock.index;
    } else {
      lastIndex = lines.length - 1;
    }
    console.log(
      '[NGFW] Bootstrapped audit chain. Last index:',
      lastIndex,
      'Last hash:',
      lastHash
    );
  } catch (err) {
    console.error('[NGFW] Failed to bootstrap audit chain:', err.message);
    lastHash = null;
    lastIndex = -1;
  }
}

function appendToAuditChain(entry) {
  try {
    const ctx = entry.context || {};
    const dec = entry.decision || {};
    const tls = entry.tls || {};

    const block = {
      index: lastIndex + 1,
      timestamp: entry.time || new Date().toISOString(),
      ctx: {
        method: ctx.method,
        path: ctx.path,
        rawPath: ctx.rawPath,
        ip: ctx.ip,
        userId: ctx.userId,
        role: ctx.role,
        userAgent: ctx.userAgent,
      },
      tls: {
        version: tls.version || null,
        cipher: tls.cipher || null,
        risk: tls.risk || null,
      },
      decision: {
        allow: !!dec.allow,
        action: dec.action,
        risk: dec.risk,
        label: dec.label,
        policy_level: dec.policy_level,
        rule_risk: entry.ruleRisk,
        ml_risk: entry.mlRisk,
        tls_risk: entry.tlsRisk,
        sig_risk: entry.sigRisk,
        ddos_risk: entry.ddosRisk,
        reasons: dec.reasons || entry.reasons || [],
      },
      statusCode: entry.statusCode ?? null,
      prevHash: lastHash,
    };

    block.hash = computeHash(block);
    fs.appendFileSync(CHAIN_FILE, JSON.stringify(block) + '\n');
    lastHash = block.hash;
    lastIndex = block.index;
  } catch (err) {
    console.error('[NGFW] Failed to append to audit chain:', err.message);
  }
}

function loadFullChain() {
  if (!fs.existsSync(CHAIN_FILE)) return [];
  const content = fs.readFileSync(CHAIN_FILE, 'utf8').trim();
  if (!content) return [];
  return content
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function verifyChain() {
  const chain = loadFullChain();
  let prevHash = null;

  for (let i = 0; i < chain.length; i++) {
    const block = chain[i];
    if (block.prevHash !== prevHash) {
      return {
        ok: false,
        brokenAt: i,
        reason: 'prevHash mismatch',
        length: chain.length,
      };
    }
    const recalculated = computeHash(block);
    if (recalculated !== block.hash) {
      return {
        ok: false,
        brokenAt: i,
        reason: 'hash mismatch',
        length: chain.length,
      };
    }
    prevHash = block.hash;
  }

  return {
    ok: true,
    brokenAt: null,
    reason: null,
    length: chain.length,
  };
}

// ---------------- CONTEXT / RBAC / RULE RISK ----------------

function buildContext(req) {
  const socket = req.socket || req.connection;
  const ip =
    req.ip ||
    req.headers['x-forwarded-for'] ||
    (socket && socket.remoteAddress) ||
    'unknown';

  let tlsVersion = 'unknown';
  let tlsCipher = 'unknown';
  if (socket && typeof socket.getProtocol === 'function') {
    tlsVersion = socket.getProtocol() || 'unknown';
  }
  if (socket && typeof socket.getCipher === 'function') {
    const c = socket.getCipher();
    tlsCipher = (c && c.name) || 'unknown';
  }

  const fp = req.tlsFingerprint || {};
  const ja3_bot_score =
    typeof fp.botScore === 'number' ? fp.botScore : 0.0;
  const tls_signals_count =
    Array.isArray(fp.signals) ? fp.signals.length : 0;

  return {
    ip,
    method: req.method,
    path: req.path,
    rawPath: req.originalUrl || req.url || req.path,
    userAgent: req.headers['user-agent'] || 'unknown',
    timestamp: new Date().toISOString(),
    userId: req.headers['x-user-id'] || 'anonymous',
    role: req.headers['x-user-role'] || 'guest',
    risk_rule: 0.0,
    tls_version: tlsVersion,
    tls_cipher: tlsCipher,
    ja3Lite: fp.ja3Lite || null,
    ja3_bot_score,
    tls_signals_count,
  };
}

// RBAC table (mutable so /admin/rbac can update it)

let RBAC = {
  guest: {
    allow: ['/info'],
    deny: ['/admin', '/admin/secret', '/admin', '/honeypot'],
  },
  user: {
    allow: ['/info', '/profile'],
    deny: ['/admin', '/admin/'],
  },
  admin: {
    allow: ['*'],
    deny: [],
  },
};

function normalizeRBAC(rbacInput) {
  const out = {};
  for (const [role, conf] of Object.entries(rbacInput || {})) {
    out[role] = {
      allow: Array.isArray(conf.allow) ? conf.allow : [],
      deny: Array.isArray(conf.deny) ? conf.deny : [],
    };
  }
  return out;
}

function checkRBAC(role, pathReq) {
  const rules = RBAC[role] || RBAC.guest;

  if (rules.allow.includes('*')) return true;

  for (const d of rules.deny) {
    const prefix = d.replace('*', '');
    if (prefix && pathReq.startsWith(prefix)) {
      return false;
    }
  }

  for (const a of rules.allow) {
    const prefix = a.replace('*', '');
    if (prefix && pathReq.startsWith(prefix)) {
      return true;
    }
  }

  return false;
}

async function checkRiskRule(ctx) {
  let risk = 0.0;
  const reasons = [];

  if (!ctx.userId || ctx.userId === 'anonymous') {
    risk += 0.15;
    reasons.push('no_user_id');
  }

  if (ctx.path.startsWith('/admin')) {
    risk += 0.45;
    reasons.push('admin_path');
  }

  if (ctx.path.startsWith('/admin') && ctx.role === 'guest') {
    risk += 0.25;
    reasons.push('guest_on_admin_path');
  }

  if (ctx.path.startsWith('/honeypot')) {
    risk += 0.75;
    reasons.push('honeypot_path');
  }

  // Simple SQLi pattern detection on the raw URL
  const raw = (ctx.rawPath || '').toLowerCase();
  if (
    raw.includes(" or 1=1") ||
    raw.includes("' or '1'='1") ||
    raw.includes('union select') ||
    raw.includes('sleep(')
  ) {
    risk += 0.6;
    reasons.push('sqli_pattern');
  }

  if (risk > 1.0) risk = 1.0;
  ctx.risk_rule = risk;

  let label = 'normal';
  if (risk >= 0.7) label = 'high_risk';
  else if (risk >= 0.35) label = 'medium_risk';

  return { risk, label, reasons };
}

// ---------------- DDoS / RATE-LIMIT RISK ----------------

function updateRateTable(ctx) {
  const key = ctx.ip || ctx.userId || 'unknown';
  const now = Date.now();
  let entry = rateTable.get(key);

  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    entry = { windowStart: now, count: 0 };
  }
  entry.count += 1;
  rateTable.set(key, entry);

  let risk = 0.0;
  const reasons = [];

  if (entry.count > RATE_LIMIT) {
    const overflow = entry.count - RATE_LIMIT;
    risk = Math.min(1.0, overflow / 20); // up to +1.0 if flood is heavy
    reasons.push('ddos_rate_limit');
  }

  return { ddosRisk: risk, ddosReasons: reasons, count: entry.count };
}

// ---------------- ML SCORING ----------------

async function scoreWithML(ctx) {
  try {
    const res = await axios.post(
      ML_SCORE_URL,
      {
        method: ctx.method,
        path: ctx.path,
        role: ctx.role,
        userId: ctx.userId,
        userAgent: ctx.userAgent,
        risk_rule: ctx.risk_rule,
        tls_version: ctx.tls_version,
        tls_cipher: ctx.tls_cipher,
        ja3_bot_score: ctx.ja3_bot_score || 0.0,
        tls_signals_count: ctx.tls_signals_count || 0,
      },
      { validateStatus: () => true, timeout: 1500 }
    );

    return {
      ml_risk:
        typeof res.data?.ml_risk === 'number' ? res.data.ml_risk : 0.0,
      ml_label: res.data?.ml_label || 'normal',
      policy_level: res.data?.policy_level || null,
    };
  } catch (err) {
    console.error('[NGFW] ML service error:', err.message);
    return { ml_risk: 0.0, ml_label: 'ml_unavailable', policy_level: null };
  }
}

// ---------------- POLICY DECISION ----------------

function computePolicyDecision({
  rbacAllowed,
  ruleDecision,
  ml,
  tlsRisk,
  sigDecision,
  ddosRisk,
}) {
  const mlRisk = typeof ml.ml_risk === 'number' ? ml.ml_risk : 0.0;
  const sigRisk = sigDecision.risk || 0.0;
  const ddos = ddosRisk || 0.0;

  let combinedRisk = mlRisk + 0.5 * sigRisk + 0.3 * tlsRisk + 0.6 * ddos;
  if (combinedRisk > 1.0) combinedRisk = 1.0;

  let action = 'ALLOW';
  let label = 'normal';

  if (!rbacAllowed) {
    action = 'RBAC_BLOCK';
    label = 'rbac_block';
    combinedRisk = Math.max(combinedRisk, 1.0);
  } else if (sigDecision.hardBlock) {
    action = 'BLOCK';
    label = 'high_risk';
    combinedRisk = Math.max(combinedRisk, 0.95);
  } else if (combinedRisk >= 0.9) {
    action = 'BLOCK';
    label = 'high_risk';
  } else if (combinedRisk >= 0.6) {
    action = 'FLAG';
    label = 'medium_risk';
  }

  if (ml.policy_level === 'level_3_block') {
    action = 'BLOCK';
    label = 'high_risk';
    combinedRisk = Math.max(combinedRisk, 0.95);
  } else if (ml.policy_level === 'level_2_restrict' && action === 'ALLOW') {
    action = 'FLAG';
    label = 'medium_risk';
  }

  const allow = rbacAllowed && action !== 'BLOCK';

  return {
    allow,
    action,
    label,
    risk: combinedRisk,
    policy_level: ml.policy_level || null,
  };
}

// ---------------- LOG HELPERS / SIEM EXPORT ----------------

function pushLog(entry) {
  auditLogs.push(entry);
  if (auditLogs.length > MAX_LOGS) {
    auditLogs.shift();
  }
  appendToAuditChain(entry);
}

function normalizeLogForSIEM(entry) {
  const ctx = entry.context || {};
  const dec = entry.decision || {};
  const tls = entry.tls || {};
  const sigs = entry.signatures || {};

  return {
    timestamp: entry.time,
    method: ctx.method,
    path: ctx.rawPath || ctx.path,
    ip: ctx.ip,
    userId: ctx.userId,
    role: ctx.role,
    userAgent: ctx.userAgent,
    statusCode: entry.statusCode,
    decision_action: dec.action,
    decision_label: dec.label,
    decision_allow: dec.allow,
    decision_risk: dec.risk,
    policy_level: dec.policy_level,
    rule_risk: entry.ruleRisk,
    ml_risk: entry.mlRisk,
    tls_risk: entry.tlsRisk,
    sig_risk: entry.sigRisk,
    ddos_risk: entry.ddosRisk,
    tls_version: tls.version,
    tls_cipher: tls.cipher,
    sig_reasons: Array.isArray(sigs.reasons)
      ? sigs.reasons.join(';')
      : '',
    reasons: Array.isArray(entry.reasons)
      ? entry.reasons.join(';')
      : '',
  };
}

function logsToCSV(logs) {
  if (!logs.length) return '';
  const rows = logs.map(normalizeLogForSIEM);
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(',')];
  for (const row of rows) {
    const line = headers
      .map((h) => JSON.stringify(row[h] ?? ''))
      .join(',');
    lines.push(line);
  }
  return lines.join('\n');
}

// ---------------- ADMIN ENDPOINTS ----------------

function createAdminEndpoints(app) {
  app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      service: 'AI-NGFW Gateway',
      time: new Date().toISOString(),
      logCount: auditLogs.length,
    });
  });

  app.get('/admin/logs', (req, res) => {
    const limitParam = parseInt(req.query.limit, 10);
    const limit = Number.isNaN(limitParam)
      ? 200
      : Math.max(1, Math.min(limitParam, MAX_LOGS));

    const logs = auditLogs.slice(-limit).reverse();
    res.json({ logs });
  });

  app.get('/admin/logs/export', (req, res) => {
    const format = String(req.query.format || 'csv').toLowerCase();
    try {
      if (format === 'json') {
        const normalized = auditLogs.map(normalizeLogForSIEM);
        const body = JSON.stringify(normalized, null, 2);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader(
          'Content-Disposition',
          'attachment; filename="ngfw_logs.json"'
        );
        return res.send(body);
      }

      const csv = logsToCSV(auditLogs);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="ngfw_logs.csv"'
      );
      res.send(csv);
    } catch (err) {
      console.error('[NGFW] Failed to export logs:', err.message);
      res.status(500).json({ error: 'EXPORT_FAILED' });
    }
  });

  app.get('/admin/policy/recommend', async (req, res) => {
    try {
      const response = await axios.get(ML_POLICY_URL, { timeout: 5000 });
      res.json(response.data);
    } catch (err) {
      console.error('[NGFW] Policy recommendation error:', err.message);
      res.status(502).json({
        error: 'POLICY_RECOMMENDATION_FAILED',
        message: 'ML policy engine not reachable',
        details: err.message,
      });
    }
  });

  // RBAC admin API
  app.get('/admin/rbac', (req, res) => {
    res.json(RBAC);
  });

  app.post('/admin/rbac', (req, res) => {
    try {
      const body = req.body || {};
      if (!body.rbac || typeof body.rbac !== 'object') {
        return res.status(400).json({ error: 'rbac object is required' });
      }
      RBAC = normalizeRBAC(body.rbac);
      res.json({ ok: true, rbac: RBAC });
    } catch (err) {
      console.error('[NGFW] Failed to update RBAC:', err.message);
      res.status(500).json({ error: 'RBAC_UPDATE_FAILED' });
    }
  });

  // Chain endpoints + public verify
  app.get('/admin/chain', (req, res) => {
    const chain = loadFullChain();
    res.json({ length: chain.length, chain });
  });

  app.get('/admin/chain/status', (req, res) => {
    const result = verifyChain();
    res.json({
      ok: result.ok,
      length: result.length,
      lastIndex,
      lastHash,
      reason: result.reason,
    });
  });

  app.get('/verify-chain', (req, res) => {
    const result = verifyChain();
    res.json(result);
  });
}

// ---------------- MAIN FIREWALL ROUTE ----------------

async function inspectAndForward(req, res) {
  const ctx = buildContext(req);
  const forwardPath = req.url.replace(/^\/fw/, '');
  const target = BACKEND_URL + forwardPath;

  const sigDecision = evaluateSignatures(ctx, req);
  const sigRisk = sigDecision.risk;
  const sigReasons = sigDecision.reasons;

  // DDoS / rate-limit risk
  const { ddosRisk, ddosReasons } = updateRateTable(ctx);

  let tlsRisk = 0.0;
  const tlsReasons = [];

  if (req.tlsFingerprint?.botScore) {
    tlsRisk += req.tlsFingerprint.botScore;
    tlsReasons.push('ja3_bot_score');
  }

  const tlsVersion = ctx.tls_version;
  const cipherName = ctx.tls_cipher;

  if (tlsVersion && !tlsVersion.includes('TLSv1.2') && !tlsVersion.includes('TLSv1.3')) {
    tlsRisk += 0.25;
    tlsReasons.push('weak_tls_version');
  }

  if (
    cipherName &&
    (cipherName.includes('RC4') || cipherName.includes('CBC') || cipherName.includes('3DES'))
  ) {
    tlsRisk += 0.30;
    tlsReasons.push('weak_cipher_suite');
  }

  const ua = (req.headers['user-agent'] || '').toLowerCase();
  if (
    (ua.includes('curl') || ua.includes('wget') || ua.includes('python-urllib')) &&
    ctx.role === 'guest'
  ) {
    tlsRisk += 0.15;
    tlsReasons.push('suspicious_ua');
  }

  // Special header to simulate TLS bot / scanner attack from the dummy site
  if (req.headers['x-ngfw-sim-tls-bot'] === '1') {
    tlsRisk += 0.6;
    tlsReasons.push('simulated_tls_bot');
  }

  if (tlsRisk > 1.0) tlsRisk = 1.0;

  const ruleDecision = await checkRiskRule(ctx);
  const ml = await scoreWithML(ctx);
  const rbacAllowed = checkRBAC(ctx.role, forwardPath);

  const decision = computePolicyDecision({
    rbacAllowed,
    ruleDecision,
    ml,
    tlsRisk,
    sigDecision,
    ddosRisk,
  });

  const baseEntry = {
    time: new Date().toISOString(),
    context: ctx,
    tls: {
      risk: tlsRisk,
      reasons: tlsReasons,
      fingerprint: req.tlsFingerprint,
      version: tlsVersion,
      cipher: cipherName,
    },
    signatures: {
      risk: sigRisk,
      reasons: sigReasons,
      hardBlock: sigDecision.hardBlock,
    },
    decision: {
      allow: decision.allow,
      action: decision.action,
      label: decision.label,
      risk: decision.risk,
      policy_level: decision.policy_level,
      rbac: rbacAllowed,
      reasons: [
        ...ruleDecision.reasons,
        ...tlsReasons,
        ...sigReasons,
        ...ddosReasons,
      ],
    },
    targetPath: forwardPath,
    ruleRisk: ruleDecision.risk,
    mlRisk: ml.ml_risk,
    tlsRisk,
    sigRisk,
    ddosRisk,
    reasons: [
      ...ruleDecision.reasons,
      ...tlsReasons,
      ...sigReasons,
      ...ddosReasons,
    ],
  };

  if (!decision.allow) {
    const blockedEntry = { ...baseEntry, statusCode: 403 };
    pushLog(blockedEntry);

    return res.status(403).json({
      error: 'Access denied by AI-NGFW',
      reason: !rbacAllowed
        ? 'RBAC violation'
        : sigDecision.hardBlock
        ? 'Matched high-confidence signature'
        : ddosRisk > 0
        ? 'Rate limit / DDoS protection'
        : 'ML policy engine classified as high risk',
      risk: decision.risk,
      tlsRisk,
      sigRisk,
      ddosRisk,
      policy_level: decision.policy_level,
      reasons: blockedEntry.reasons,
    });
  }

  try {
    const response = await axios({
      method: req.method,
      url: target,
      data: req.body,
      headers: { ...req.headers, host: undefined },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
        keepAlive: true,
      }),
      validateStatus: () => true,
      timeout: 10000,
    });

    const allowedEntry = { ...baseEntry, statusCode: response.status };
    pushLog(allowedEntry);

    res.set('x-ngfw-rule-risk', String(ruleDecision.risk));
    res.set('x-ngfw-ml-risk', String(ml.ml_risk));
    res.set('x-ngfw-tls-risk', String(tlsRisk));
    res.set('x-ngfw-sig-risk', String(sigRisk));
    res.set('x-ngfw-ddos-risk', String(ddosRisk));
    res.set('x-ngfw-final-risk', String(decision.risk));
    res.set('x-ngfw-label', decision.label);

    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error('[NGFW] Backend error:', err.message);
    const errorEntry = { ...baseEntry, statusCode: 500, error: err.message };
    pushLog(errorEntry);
    return res.status(500).json({ error: 'TLS Backend unavailable' });
  }
}

// ---------------- TLS CERTS & SERVER BOOTSTRAP ----------------

function ensureCerts() {
  return new Promise((resolve, reject) => {
    const keyPath = path.join(__dirname, 'key.pem');
    const certPath = path.join(__dirname, 'cert.pem');

    if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
      console.log('[NGFW] Using existing gateway TLS certs.');
      return resolve();
    }

    pem.createCertificate(
      { days: 365, selfSigned: true, keyBits: 2048 },
      (err, keys) => {
        if (err) return reject(err);
        fs.writeFileSync(keyPath, keys.serviceKey);
        fs.writeFileSync(certPath, keys.certificate);
        console.log('[NGFW] Generated self-signed TLS certs (key.pem, cert.pem)');
        resolve();
      }
    );
  });
}

async function startServer() {
  bootstrapChain();
  await ensureCerts();

  const app = express();
  app.use(express.json());
  app.use(cors({ origin: true, credentials: false }));
  app.use(morgan('dev'));
  app.set('trust proxy', true);

  // Attach TLS / JA3-lite fingerprint
  app.use((req, res, next) => {
    try {
      const socket = req.socket || req.connection;
      const peerCert =
        socket && typeof socket.getPeerCertificate === 'function'
          ? socket.getPeerCertificate(false) || {}
          : {};

      const tlsInfo = {
        version:
          (socket && typeof socket.getProtocol === 'function' && socket.getProtocol()) ||
          'unknown',
        cipher:
          (socket && typeof socket.getCipher === 'function' && socket.getCipher()?.name) ||
          'unknown',
        sni: socket?.servername || req.headers.host || 'unknown',
        issuer: (peerCert.issuer && peerCert.issuer.CN) || 'unknown',
        subject: (peerCert.subject && peerCert.subject.CN) || 'unknown',
      };

      const ja3Lite = [
        String(tlsInfo.version || '').replace('TLSv', ''),
        tlsInfo.cipher || '',
        tlsInfo.sni || '',
        tlsInfo.issuer || '',
      ]
        .join('|')
        .slice(0, 64);

      const fp = {
        ja3Lite,
        botScore: 0.0,
        signals: [],
        tlsInfo,
      };

      const ua = (req.headers['user-agent'] || '').toLowerCase();
      if (
        ua.includes('curl') ||
        ua.includes('python-urllib') ||
        ua.includes('wget') ||
        ua.includes('node-fetch')
      ) {
        fp.botScore += 0.35;
        fp.signals.push('scripted_ua');
      }

      if (
        tlsInfo.cipher &&
        (tlsInfo.cipher.includes('RC4') ||
          tlsInfo.cipher.includes('CBC') ||
          tlsInfo.cipher.includes('3DES'))
      ) {
        fp.botScore += 0.25;
        fp.signals.push('weak_cipher');
      }

      if (
        !tlsInfo.sni ||
        tlsInfo.sni === 'localhost' ||
        tlsInfo.sni === '127.0.0.1'
      ) {
        fp.botScore += 0.1;
        fp.signals.push('local_sni');
      }

      if (!tlsInfo.issuer || /self-signed/i.test(String(tlsInfo.issuer))) {
        fp.botScore += 0.15;
        fp.signals.push('selfsigned_cert');
      }

      req.tlsFingerprint = fp;
    } catch (err) {
      console.log('[NGFW] TLS fingerprint error:', err.message);
    }
    next();
  });

  createAdminEndpoints(app);
  app.use('/fw', inspectAndForward);

  const key = fs.readFileSync(path.join(__dirname, 'key.pem'));
  const cert = fs.readFileSync(path.join(__dirname, 'cert.pem'));

  https.createServer({ key, cert }, app).listen(PORT, () => {
    console.log(`AI-NGFW Gateway running at https://localhost:${PORT}`);
    console.log(`Admin logs: https://localhost:${PORT}/admin/logs`);
    console.log(`Verify chain: https://localhost:${PORT}/verify-chain`);
    console.log(`Traffic proxy: https://localhost:${PORT}/fw/*`);
  });
}

startServer().catch((err) => {
  console.error('[NGFW] Fatal error starting gateway:', err);
  process.exit(1);
});
