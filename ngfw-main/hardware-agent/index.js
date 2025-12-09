/**
 * AI‑NGFW Hardware Agent
 * ----------------------
 * This script is what we would run on a hardware firewall appliance
 * (Linux-based router, NIC box, etc.).
 *
 * It:
 *   1. Polls the AI‑NGFW gateway for recent logs.
 *   2. Detects IPs generating many high‑risk / blocked events.
 *   3. Pushes iptables DROP rules into the hardware (or prints them
 *      in demo mode).
 *
 * In a real company device, “iptables” would be replaced by:
 *   - The vendor’s SDK
 *   - ASIC / FPGA API
 *   - Router CLI / netlink calls
 */

const axiosRaw = require('axios');
const https = require('https');
const { exec } = require('child_process');

// ---------------- CONFIG ----------------

// Where our AI‑NGFW gateway runs
const GATEWAY_URL = process.env.GATEWAY_URL || 'https://localhost:4001';

// How often to poll logs
const POLL_INTERVAL_MS = 10_000; // 10 seconds

// Only consider events from the last LOOKBACK_MS
const LOOKBACK_MS = 5 * 60 * 1000; // 5 minutes

// If an IP has >= BLOCK_THRESHOLD high‑risk/blocked events in window => block
const BLOCK_THRESHOLD = 10;

// Whether we actually apply iptables rules
// By default we are in DRY RUN to avoid breaking the dev machine.
// On a real appliance you would set APPLY_RULES=true.
const isLinux = process.platform === 'linux';
const APPLY_RULES = process.env.APPLY_RULES === 'true' && isLinux;

console.log('=== AI‑NGFW Hardware Agent ===');
console.log('Gateway URL:', GATEWAY_URL);
console.log('Apply iptables rules:', APPLY_RULES ? 'YES' : 'NO (dry run)');
console.log('Platform:', process.platform);

// Axios instance that trusts our self‑signed gateway cert
const axios = axiosRaw.create({
  baseURL: GATEWAY_URL,
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 8000
});

// Track which IPs we’ve already blocked (ip -> { blockedAt, reason, count })
const blockedIPs = new Map();

// ---------------- HELPERS ----------------

async function fetchRecentLogs() {
  try {
    const res = await axios.get('/admin/logs?limit=500', {
      headers: { Accept: 'application/json' }
    });

    const logs = res.data?.logs || res.data || [];
    const now = Date.now();

    return logs.filter((entry) => {
      if (!entry.time) return false;
      const t = new Date(entry.time).getTime();
      if (Number.isNaN(t)) return false;
      return now - t <= LOOKBACK_MS;
    });
  } catch (err) {
    console.error('[AGENT] Failed to fetch logs from gateway:', err.message);
    return [];
  }
}

/**
 * Calculate per‑IP “bad behavior” scores based on recent logs
 * and decide which IPs should be blocked.
 */
function calculateOffenders(logs) {
  const scores = new Map(); // ip -> { highRiskCount, blockedCount, lastSeen }

  for (const entry of logs) {
    const ip =
      entry.context?.ip ||
      entry.context?.l4?.srcIp ||
      'unknown';

    if (!ip || ip === 'unknown') continue;

    const label = entry.decision?.label || 'normal';
    const risk = typeof entry.decision?.risk === 'number'
      ? entry.decision.risk
      : 0;
    const blocked = !entry.decision?.allow || entry.statusCode >= 400;

    let rec = scores.get(ip);
    if (!rec) {
      rec = { highRiskCount: 0, blockedCount: 0, lastSeen: entry.time };
    }

    if (label === 'high_risk' || label === 'rbac_block' || risk >= 0.9) {
      rec.highRiskCount += 1;
    }
    if (blocked) {
      rec.blockedCount += 1;
    }

    rec.lastSeen = entry.time || rec.lastSeen;
    scores.set(ip, rec);
  }

  const offenders = [];

  for (const [ip, rec] of scores.entries()) {
    const score = rec.highRiskCount + rec.blockedCount;
    if (score >= BLOCK_THRESHOLD) {
      offenders.push({ ip, score, info: rec });
    }
  }

  return offenders;
}

/**
 * Actually apply (or simulate) iptables DROP rules.
 */
function applyIptablesDrop(ip) {
  const cmd = `iptables -I INPUT -s ${ip} -j DROP`;

  if (!APPLY_RULES) {
    console.log(`[AGENT][DRY] Would apply: ${cmd}`);
    return;
  }

  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      console.error('[AGENT] iptables command failed:', err.message);
      return;
    }
    if (stdout.trim()) console.log('[AGENT] iptables stdout:', stdout.trim());
    if (stderr.trim()) console.log('[AGENT] iptables stderr:', stderr.trim());
    console.log('[AGENT] Applied hardware DROP rule for', ip);
  });
}

/**
 * Optionally remove old rules (demo only – in real appliance you’d
 * use more advanced lifetime / reputational logic).
 */
function simulateUnblockOldIPs() {
  const now = Date.now();
  const UNBLOCK_AFTER_MS = 60 * 60 * 1000; // 1 hour

  for (const [ip, meta] of blockedIPs.entries()) {
    if (now - meta.blockedAt > UNBLOCK_AFTER_MS) {
      const cmd = `iptables -D INPUT -s ${ip} -j DROP`;
      if (!APPLY_RULES) {
        console.log(`[AGENT][DRY] Would remove: ${cmd}`);
      } else {
        exec(cmd, () => {
          console.log('[AGENT] (simulated) removing DROP rule for', ip);
        });
      }
      blockedIPs.delete(ip);
    }
  }
}

// ---------------- MAIN LOOP ----------------

async function hardwarePolicyLoop() {
  try {
    const logs = await fetchRecentLogs();
    if (!logs.length) {
      console.log('[AGENT] No recent logs – nothing to do.');
      return;
    }

    const offenders = calculateOffenders(logs);
    if (!offenders.length) {
      console.log('[AGENT] No IPs exceed threshold yet.');
      simulateUnblockOldIPs();
      return;
    }

    for (const offender of offenders) {
      const ip = offender.ip;
      const already = blockedIPs.get(ip);

      if (already) {
        // already blocked, just update stats
        already.score = offender.score;
        continue;
      }

      console.log(
        `[AGENT] IP ${ip} exceeded threshold: highRisk+blocked=${offender.score}. Pushing hardware block.`
      );
      blockedIPs.set(ip, {
        blockedAt: Date.now(),
        score: offender.score
      });

      applyIptablesDrop(ip);
    }

    simulateUnblockOldIPs();
  } catch (err) {
    console.error('[AGENT] Error in main loop:', err.message);
  }
}

// Kick off
(async () => {
  console.log('[AGENT] Starting hardware policy loop (interval:', POLL_INTERVAL_MS, 'ms )');
  await hardwarePolicyLoop();
  setInterval(hardwarePolicyLoop, POLL_INTERVAL_MS);
})();
