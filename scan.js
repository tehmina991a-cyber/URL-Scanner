// Vercel serverless function — same job as server.js's /api/scan route,
// but written as a standalone function (no Express) since that's what
// Vercel expects for files under /api. Deployed, this becomes:
//   POST https://<your-project>.vercel.app/api/scan

const VT_BASE = 'https://www.virustotal.com/api/v3';

function b64url(str) {
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function vt(path, apiKey, opts = {}) {
  return fetch(VT_BASE + path, {
    method: opts.method || 'GET',
    headers: Object.assign({ 'x-apikey': apiKey }, opts.headers || {}),
    body: opts.body
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  const { apiKey, url } = req.body || {};
  if (!apiKey || !url) {
    res.status(400).json({ error: 'MISSING_FIELDS', message: 'apiKey and url are both required.' });
    return;
  }

  const urlId = b64url(url);

  try {
    const existing = await vt('/urls/' + urlId, apiKey);
    if (existing.status === 401) {
      res.status(401).json({ error: 'AUTH', message: 'VirusTotal rejected this API key.' });
      return;
    }
    if (existing.status === 200) {
      const json = await existing.json();
      res.status(200).json({ cached: true, urlId, data: json.data });
      return;
    }

    // No existing record — submit a fresh scan.
    const submitted = await vt('/urls', apiKey, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'url=' + encodeURIComponent(url)
    });
    if (submitted.status === 401) {
      res.status(401).json({ error: 'AUTH', message: 'VirusTotal rejected this API key.' });
      return;
    }
    if (submitted.status === 429) {
      res.status(429).json({ error: 'RATE_LIMIT', message: 'VirusTotal rate limit hit while submitting the URL.' });
      return;
    }
    if (!submitted.ok) {
      res.status(502).json({ error: 'HTTP_' + submitted.status });
      return;
    }
    const submittedJson = await submitted.json();
    const analysisId = submittedJson.data.id;

    // Poll for completion — up to ~60s, spaced to respect the public
    // API's 4-requests-per-minute limit. Vercel's default function
    // duration comfortably covers this (see vercel.json for the
    // explicit maxDuration set as a safety net on older accounts).
    let completed = null;
    for (let i = 0; i < 4; i++) {
      await sleep(15000);
      const analysisRes = await vt('/analyses/' + analysisId, apiKey);
      if (analysisRes.status === 401) {
        res.status(401).json({ error: 'AUTH', message: 'VirusTotal rejected this API key.' });
        return;
      }
      if (analysisRes.status === 429) {
        res.status(429).json({ error: 'RATE_LIMIT', message: 'VirusTotal rate limit hit while polling for results.' });
        return;
      }
      if (!analysisRes.ok) {
        res.status(502).json({ error: 'HTTP_' + analysisRes.status });
        return;
      }
      const analysisJson = await analysisRes.json();
      if (analysisJson.data.attributes.status === 'completed') {
        completed = analysisJson;
        break;
      }
    }

    if (!completed) {
      res.status(504).json({
        error: 'TIMEOUT',
        message: 'Still queued on VirusTotal after ~60s. Try again shortly.'
      });
      return;
    }

    // Re-fetch the URL object for categories/reputation/WHOIS/title.
    const finalRes = await vt('/urls/' + urlId, apiKey);
    if (finalRes.status === 200) {
      const finalJson = await finalRes.json();
      res.status(200).json({ cached: false, urlId, data: finalJson.data });
      return;
    }

    res.status(200).json({
      cached: false,
      urlId,
      data: {
        attributes: {
          last_analysis_stats: completed.data.attributes.stats,
          last_analysis_results: completed.data.attributes.results,
          last_analysis_date: Math.floor(Date.now() / 1000)
        }
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'SERVER_ERROR', message: String((err && err.message) || err) });
  }
};
