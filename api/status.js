// POST /api/scan   { url }
//
// Returns fast, always:
//  - { status: 'completed', cached: true,  urlId, data }   — already known to VirusTotal
//  - { status: 'queued',    urlId, analysisId }              — brand-new URL, analysis kicked off;
//                                                               poll /api/status to get the result
//
// This never blocks for the ~15-60s a fresh analysis can take — that's
// the difference from a naive implementation, and it's what keeps the
// UI feeling instant instead of frozen on a spinner.

const {
  b64url,
  vt,
  validateUrl,
  checkGlobalLimit,
  recordGlobalHit,
  checkIpLimit,
  recordIpHit,
  getClientIp,
  setCommonHeaders
} = require('./_lib');

module.exports = async (req, res) => {
  setCommonHeaders(res);

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  const body = req.body || {};
  const check = validateUrl(body.url);
  if (!check.ok) {
    res.status(400).json({ error: 'INVALID_URL', message: check.message });
    return;
  }
  const url = check.url;

  const ip = getClientIp(req);
  const ipGate = checkIpLimit(ip);
  if (!ipGate.ok) {
    res.status(429).json({
      error: 'RATE_LIMIT_IP',
      message: 'You\u2019ve hit the per-visitor scan limit for this hour. Try again shortly.',
      retryAfter: ipGate.retryAfter
    });
    return;
  }

  const urlId = b64url(url);

  try {
    // Always try the cached lookup first — it's cheap and, if VirusTotal
    // already has a verdict, the visitor gets a full report in well
    // under a second with no quota spent on submission.
    const existing = await vt('/urls/' + urlId);
    if (existing.status === 401) {
      res.status(500).json({ error: 'SERVER_KEY_REJECTED', message: 'The server\u2019s VirusTotal key was rejected. The site owner needs to check VT_API_KEY.' });
      return;
    }
    if (existing.status === 200) {
      const json = await existing.json();
      res.status(200).json({ status: 'completed', cached: true, urlId, data: json.data });
      return;
    }

    // Not cached — this will cost a submission call, so gate it globally.
    const globalGate = checkGlobalLimit();
    if (!globalGate.ok) {
      res.status(429).json({
        error: 'RATE_LIMIT_GLOBAL',
        message: 'This scanner is at capacity right now (shared API quota). Try again in a few seconds.',
        retryAfter: globalGate.retryAfter
      });
      return;
    }

    recordGlobalHit();
    recordIpHit(ip);

    const submitted = await vt('/urls', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'url=' + encodeURIComponent(url)
    });

    if (submitted.status === 401) {
      res.status(500).json({ error: 'SERVER_KEY_REJECTED', message: 'The server\u2019s VirusTotal key was rejected. The site owner needs to check VT_API_KEY.' });
      return;
    }
    if (submitted.status === 429) {
      res.status(429).json({ error: 'RATE_LIMIT_UPSTREAM', message: 'VirusTotal\u2019s own rate limit was hit. Try again in a minute.' });
      return;
    }
    if (!submitted.ok) {
      res.status(502).json({ error: 'HTTP_' + submitted.status, message: 'Unexpected response from VirusTotal while submitting the URL.' });
      return;
    }

    const submittedJson = await submitted.json();
    const analysisId = submittedJson.data.id;

    res.status(200).json({ status: 'queued', urlId, analysisId });
  } catch (err) {
    if (err && err.code === 'MISSING_SERVER_KEY') {
      res.status(500).json({ error: 'MISSING_SERVER_KEY', message: err.message });
      return;
    }
    console.error(err);
    res.status(500).json({ error: 'SERVER_ERROR', message: String((err && err.message) || err) });
  }
};
