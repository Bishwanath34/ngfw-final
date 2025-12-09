require('dotenv').config();
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
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:9001';
const ML_SCORE_URL = process.env.ML_SCORE_URL || 'http://localhost:5000/score';
const SIGNATURES_PATH = path.join(__dirname, 'signatures.json');
const DB_DIR = path.join(__dirname, '..', 'db');
const CHAIN_FILE = path.join(DB_DIR, 'audit_chain.jsonl');

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

let auditLogs = [];
const MAX_LOGS = 5000;

// ---------------- SIGNATURE ENGINE ----------------
let signatureCache = { loadedAt: null, mtimeMs: 0, signatures: [] };

function loadSignaturesFromDisk() {
  try {
    const stat = fs.statSync(SIGNATURES_PATH);
    if (signatureCache.mtimeMs === stat.mtimeMs && signatureCache.signatures.length) {
      return signatureCache.signatures;
    }
    const raw = fs.readFileSync(SIGNATURES_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    const sigs = Array.isArray(parsed.signatures) ? parsed.signatures : [];
    signatureCache = { loadedAt: new Date(), mtimeMs: stat.mtimeMs, signatures: sigs };
    console.log('[NGFW] Loaded', sigs.length, 'signatures from disk');
    return sigs;
  } catch {
    return signatureCache.signatures;
  }
}

function evaluateSignatures(ctx, req) {
  const sigs = loadSignaturesFromDisk();
  let risk = 0.0;
  const reasons = [];
  let hardBlock = false;

  for (const sig of sigs) {
    const id = sig.id || sig.name || 'signature';
    let matched = false;

    if (sig.pathContains && ctx.path.includes(sig.pathContains)) matched = true;
    if (!matched && sig.pathRegex) {
      try {
        const re = new RegExp(sig.pathRegex, 'i');
        if (re.test(ctx.path)) matched = true;
      } catch {}
    }
    if (!matched) continue;

    risk += typeof sig.risk === 'number' ? sig.risk : 0.3;
    reasons.push(`sig:${id}`);
    if (sig.action === 'block' || sig.action === 'hard_block') hardBlock = true;
  }

  if (risk > 1.0) risk = 1.0;
  return { risk, reasons, hardBlock };
}

// ---------------- AUDIT CHAIN ----------------
let lastHash = null;
let lastIndex = -1;

function computeHash(block) {
  const copy = { ...block };
  delete copy.hash;
  return crypto.createHash('sha256').update(JSON.stringify(copy)).digest('hex');
}

function appendToAuditChain(entry) {
  const block = {
    index: lastIndex + 1,
    timestamp: entry.time,
    context: entry.context,
    tls: entry.tls,
    decision: entry.decision,
    statusCode: entry.statusCode,
    prevHash: lastHash,
  };
  block.hash = computeHash(block);
  fs.appendFileSync(CHAIN_FILE, JSON.stringify(block) + '\n');
  lastHash = block.hash;
  lastIndex = block.index;
}

// ---------------- RBAC ----------------
let RBAC = {
  guest: { allow: ['/info'], deny: ['/admin', '/honeypot'] },
  user: { allow: ['/info', '/profile'], deny: ['/admin'] },
  admin: { allow: ['*'], deny: [] },
};

function checkRBAC(role, path) {
  const rules = RBAC[role] || RBAC.guest;
  if (rules.allow.includes('*')) return true;
  if (rules.deny.some((d) => path.startsWith(d))) return false;
  return rules.allow.some((a) => path.startsWith(a));
}

// ---------------- ML RISK SCORING ----------------
async function scoreWithML(ctx) {
  try {
    const res = await axios.post(
      ML_SCORE_URL,
      { method: ctx.method, path: ctx.path, role: ctx.role, userAgent: ctx.userAgent },
      { timeout: 1500 }
    );
    return {
      ml_risk: res.data?.ml_risk ?? 0.0,
      ml_label: res.data?.ml_label ?? 'normal',
      policy_level: res.data?.policy_level ?? null,
    };
  } catch {
    return { ml_risk: 0.0, ml_label: 'ml_error', policy_level: null };
  }
}

// ---------------- DECISION ENGINE ----------------
function computePolicyDecision({ rbacAllowed, sigDecision, ml }) {
  let combinedRisk = ml.ml_risk + sigDecision.risk * 0.7;
  if (combinedRisk > 1.0) combinedRisk = 1.0;

  let action = 'ALLOW';
  if (!rbacAllowed) {
    action = 'RBAC_BLOCK';
  } else if (sigDecision.hardBlock || combinedRisk >= 0.9) {
    action = 'BLOCK';
  } else if (combinedRisk >= 0.6) {
    action = 'FLAG';
  }

  const allow = action === 'ALLOW' || action === 'FLAG';
  return { allow, action, risk: combinedRisk };
}

// ---------------- LOGGING ----------------
function pushLog(entry) {
  auditLogs.push(entry);
  if (auditLogs.length > MAX_LOGS) auditLogs.shift();
  appendToAuditChain(entry);
}

// ---------------- FIREWALL HANDLER ----------------
async function inspectAndForward(req, res) {
  const ctx = {
    ip: req.ip,
    method: req.method,
    path: req.path,
    rawPath: req.originalUrl,
    userAgent: req.headers['user-agent'] || 'unknown',
    role: req.headers['x-user-role'] || 'guest',
    userId: req.headers['x-user-id'] || 'anonymous',
  };

  // Remove the /fw prefix from the original URL
  const forwardPath = req.originalUrl.replace(/^\/fw/, '');
  const target = BACKEND_URL + forwardPath;

  const sigDecision = evaluateSignatures(ctx, req);
  const ml = await scoreWithML(ctx);
  const rbacAllowed = checkRBAC(ctx.role, forwardPath);

  const decision = computePolicyDecision({ rbacAllowed, sigDecision, ml });

  const logEntry = {
    time: new Date().toISOString(),
    context: ctx,
    decision,
    statusCode: decision.allow ? 200 : 403,
  };
  pushLog(logEntry);

  if (!decision.allow) {
    return res.status(403).json({ error: 'Access denied', decision });
  }

  try {
    const response = await axios({
      method: req.method,
      url: target,
      data: req.body,
      headers: req.headers,
      validateStatus: () => true,
    });
    res.status(response.status).send(response.data);
  } catch (err) {
    res.status(502).json({ error: 'BACKEND_ERROR', details: err.message });
  }
}

// ---------------- ADMIN ENDPOINTS ----------------
function createAdminEndpoints(app) {
  app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

  app.get('/admin/logs', (req, res) => {
    res.json({ logs: auditLogs.slice(-200).reverse() });
  });

  app.post('/admin/rbac', (req, res) => {
    if (!req.body.rbac) return res.status(400).json({ error: 'rbac required' });
    RBAC = req.body.rbac;
    res.json({ ok: true, RBAC });
  });
}

// ---------------- SERVER ----------------
async function start() {
  const app = express();
  app.use(express.json());
  app.use(cors());
  app.use(morgan('dev'));

  createAdminEndpoints(app);

  // <-- FIXED ROUTE HERE -->
  app.all('/fw/*', inspectAndForward);

  pem.createCertificate({ days: 365, selfSigned: true }, (err, keys) => {
    if (err) throw err;
    const server = https.createServer({ key: keys.serviceKey, cert: keys.certificate }, app);
    server.listen(PORT, () => {
      console.log(`AI-NGFW Gateway running on https://localhost:${PORT}`);
      console.log('Forwarding to backend:', BACKEND_URL);
    });
  });
}

start();
