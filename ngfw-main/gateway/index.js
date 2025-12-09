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
const ML_POLICY_URL = process.env.ML_POLICY_URL || 'http://localhost:5000/policy/recommend';

const SIGNATURES_PATH = path.join(__dirname, 'signatures.json');
const DB_DIR = path.join(__dirname, '..', 'db');
const CHAIN_FILE = path.join(DB_DIR, 'audit_chain.jsonl');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

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
  } catch (err) {
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
  if (!rbacAllowed) action = 'RBAC
