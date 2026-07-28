// URL Threat Scanner — local proxy server
//
// Browsers block direct calls to the VirusTotal API from a web page (CORS).
// This tiny server sits between the page and VirusTotal: the page calls
// this server on localhost, and the server calls VirusTotal directly
// (server-to-server requests aren't subject to browser CORS rules).
//
// Nothing here stores your API key — it's read from each request and
// discarded once that request finishes.

const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

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

// POST /api/scan  { apiKey, url }
// Returns the full VirusTotal URL object (cached lookup if one already
// exists, otherwise submits a fresh scan and polls until it completes).
app.post('/api/scan', async (req, res) => {
  const { apiKey, url } = req.body || {};
  if (!apiKey || !url) {
    return res.status(400).json({ error: 'MISSING_FIELDS', message: 'apiKey and url are both required.' });
  }

  const urlId = b64url(url);

  try {
    const existing = await vt('/urls/' + urlId, apiKey);
    if (existing.status === 401) {
      return res.status(401).json({ error: 'AUTH', message: 'VirusTotal rejected this API key.' });
    }
    if (existing.status === 200) {
      const json = await existing.json();
      return res.json({ cached: true, urlId, data: json.data });
    }

    // No existing record (404) — submit it for a fresh analysis.
    const submitted = await vt('/urls', apiKey, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'url=' + encodeURIComponent(url)
    });
    if (submitted.status === 401) {
      return res.status(401).json({ error: 'AUTH', message: 'VirusTotal rejected this API key.' });
    }
    if (submitted.status === 429) {
      return res.status(429).json({ error: 'RATE_LIMIT', message: 'VirusTotal rate limit hit while submitting the URL.' });
    }
    if (!submitted.ok) {
      return res.status(502).json({ error: 'HTTP_' + submitted.status, message: 'Unexpected response while submitting the URL.' });
    }
    const submittedJson = await submitted.json();
    const analysisId = submittedJson.data.id;

    // Poll for completion. Spaced out to stay under the public API's
    // 4-requests-per-minute limit: up to 4 checks, 15s apart (~60s total).
    let completed = null;
    for (let i = 0; i < 4; i++) {
      await sleep(15000);
      const analysisRes = await vt('/analyses/' + analysisId, apiKey);
      if (analysisRes.status === 401) {
        return res.status(401).json({ error: 'AUTH', message: 'VirusTotal rejected this API key.' });
      }
      if (analysisRes.status === 429) {
        return res.status(429).json({ error: 'RATE_LIMIT', message: 'VirusTotal rate limit hit while polling for results.' });
      }
      if (!analysisRes.ok) {
        return res.status(502).json({ error: 'HTTP_' + analysisRes.status });
      }
      const analysisJson = await analysisRes.json();
      if (analysisJson.data.attributes.status === 'completed') {
        completed = analysisJson;
        break;
      }
    }

    if (!completed) {
      return res.status(504).json({
        error: 'TIMEOUT',
        message: 'Still queued on VirusTotal after ~60s. Try again shortly, or check it directly.',
        analysisId
      });
    }

    // Re-fetch the URL object for the extra metadata (categories,
    // reputation, WHOIS, title) that only lives on that endpoint.
    const finalRes = await vt('/urls/' + urlId, apiKey);
    if (finalRes.status === 200) {
      const finalJson = await finalRes.json();
      return res.json({ cached: false, urlId, data: finalJson.data });
    }

    // Fallback: build a minimal object from the analysis alone.
    return res.json({
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
    return res.status(500).json({ error: 'SERVER_ERROR', message: String((err && err.message) || err) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('URL Threat Scanner running at http://localhost:' + PORT);
});
