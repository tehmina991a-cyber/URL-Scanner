// Shared helpers for the VirusTotal-backed API routes.
//
// The VirusTotal API key lives ONLY here, read from an environment
// variable. It is never sent to, or read from, the browser.

const VT_BASE = 'https://www.virustotal.com/api/v3';

function getApiKey() {
  const key = process.env.VT_API_KEY;
  if (!key) {
    const err = new Error(
      'VT_API_KEY is not set. Add it in your Vercel project → Settings → Environment Variables (or a local .env file), then redeploy / restart.'
    );
    err.code = 'MISSING_SERVER_KEY';
    throw err;
  }
  return key;
}

function b64url(str) {
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function vt(path, opts = {}) {
  const apiKey = getApiKey();
  return fetch(VT_BASE + path, {
    method: opts.method || 'GET',
    headers: Object.assign({ 'x-apikey': apiKey }, opts.headers || {}),
    body: opts.body
  });
}

// --- URL sanity checks -----------------------------------------------
// Blocks obviously-invalid input and requests aimed at internal/loopback
// network addresses before we ever spend a VirusTotal quota unit on them.
const BLOCKED_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);

function validateUrl(raw) {
  let candidate = String(raw || '').trim();
  if (!candidate) return { ok: false, message: 'URL is empty.' };
  if (!/^https?:\/\//i.test(candidate)) candidate = 'https://' + candidate;

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch (e) {
    return { ok: false, message: 'That does not look like a valid URL.' };
  }

  const host = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(host) || host.endsWith('.local') || host.startsWith('192.168.') || host.startsWith('10.') || host === '169.254.169.254') {
    return { ok: false, message: 'Internal/local network addresses cannot be scanned.' };
  }
  return { ok: true, url: candidate };
}

// --- Rate limiting -----------------------------------------------------
// Two layers of protection for a shared, server-owned API key:
//
// 1. GLOBAL gate — VirusTotal's free public tier allows only ~4 lookups
//    per minute *in total*, no matter how many people are using this app.
//    We track a rolling window of recent VT calls in memory and reject
//    new submissions early (fast, no hanging request) if we're at the
//    ceiling, instead of letting VirusTotal itself throw a 429 later.
//
// 2. PER-IP gate — stops one visitor from consuming the whole shared
//    quota by themselves.
//
// Caveat: this is in-memory, per serverless-instance state. It resets on
// cold start and isn't shared across concurrent instances. That's fine
// as a first line of defense for light/medium traffic; for guaranteed
// accuracy at real scale, swap this for Vercel KV / Upstash Redis (a few
// lines — see README).

const GLOBAL_WINDOW_MS = 60 * 1000;
const GLOBAL_MAX = 4; // matches VT free-tier lookups/min

const IP_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const IP_MAX = 20; // scans per IP per hour

let globalHits = [];
const ipHits = new Map();

function pruneOld(arr, windowMs) {
  const cutoff = Date.now() - windowMs;
  while (arr.length && arr[0] < cutoff) arr.shift();
}

function checkGlobalLimit() {
  pruneOld(globalHits, GLOBAL_WINDOW_MS);
  if (globalHits.length >= GLOBAL_MAX) {
    const retryAfter = Math.ceil((globalHits[0] + GLOBAL_WINDOW_MS - Date.now()) / 1000);
    return { ok: false, retryAfter: Math.max(retryAfter, 1) };
  }
  return { ok: true };
}

function recordGlobalHit() {
  globalHits.push(Date.now());
}

function checkIpLimit(ip) {
  const key = ip || 'unknown';
  let hits = ipHits.get(key) || [];
  pruneOld(hits, IP_WINDOW_MS);
  ipHits.set(key, hits);
  if (hits.length >= IP_MAX) {
    return { ok: false, retryAfter: Math.ceil((hits[0] + IP_WINDOW_MS - Date.now()) / 1000) };
  }
  return { ok: true };
}

function recordIpHit(ip) {
  const key = ip || 'unknown';
  const hits = ipHits.get(key) || [];
  hits.push(Date.now());
  ipHits.set(key, hits);
}

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.socket && req.socket.remoteAddress;
}

function setCommonHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

module.exports = {
  VT_BASE,
  b64url,
  vt,
  validateUrl,
  checkGlobalLimit,
  recordGlobalHit,
  checkIpLimit,
  recordIpHit,
  getClientIp,
  setCommonHeaders
};
