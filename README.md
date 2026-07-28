# URL Threat Scanner

A VirusTotal-backed URL scanner: a small local proxy server plus a static page. The proxy exists purely to get around browser CORS restrictions — VirusTotal's API doesn't allow direct calls from a web page, but it works fine from a server.

## Setup

```bash
npm install
node server.js
```

Then open **http://localhost:3000** in your browser.

You'll need your own VirusTotal API key (free at [virustotal.com](https://www.virustotal.com/gui/join-us) — the free tier allows ~4 requests/minute and 500/day). Paste it into the page; it's sent to your own local server on each request and never written to disk.

## What it does

- **Scan one or more URLs** (one per line). Existing VirusTotal records are used if present; otherwise it submits a fresh scan and polls until it completes.
- **Full report per URL**: detection ratio, per-engine breakdown, community categories, reputation score, WHOIS record, final URL after redirects, and HTTP response code.
- **History**, saved in your browser (`localStorage`), so past scans persist across reloads without re-querying VirusTotal.
- **Print / PDF export** per report, using the browser's own print dialog ("Save as PDF").

## Notes

- Multiple URLs are scanned one at a time with a ~16s delay between them to stay under the public API's rate limit. A single "fresh" URL (not already in VirusTotal's database) can itself take up to a minute, since the server polls for the analysis to finish.
- This server has no authentication of its own — it's meant to run on `localhost` for personal use. If you ever expose it beyond your own machine, add your own auth in front of it, since anyone who can reach it could spend your API quota.
- Free-tier keys are rate-limited; a 429 response from VirusTotal will show up in the UI as "Rate limit hit."

## Deploying to Vercel

This repo is already laid out the way Vercel expects: a static `index.html` at the root, plus a serverless function at `api/scan.js` that does the same job as `server.js` does locally. You don't need `server.js` or `express` at all for a Vercel deployment — those are only for running it on your own machine.

**Option A — Vercel CLI (fastest):**
```bash
npm install -g vercel
vercel login
vercel        # deploys a preview URL
vercel --prod # promotes to your production URL
```
Run these from inside the project folder. Vercel will detect `index.html` and `api/scan.js` automatically — no build step is needed.

**Option B — Git + Vercel dashboard:**
1. Push this folder to a GitHub (or GitLab/Bitbucket) repo.
2. Go to [vercel.com/new](https://vercel.com/new), import that repo.
3. Leave the framework preset as "Other" and click Deploy — no environment variables are required, since each visitor supplies their own VirusTotal API key in the page itself.

Either way, you'll get a URL like `https://your-project.vercel.app` that works the same as `localhost:3000` did — the only difference is `api/scan.js` runs as a Vercel serverless function instead of an Express route.

**Things worth knowing before you deploy publicly:**
- **No login screen.** Anyone with the link can open the page and scan URLs — but only using *their own* API key, which they type in themselves and which is never stored anywhere. If you want to restrict access, Vercel's Pro plan offers password-protected deployments, or you could add a simple shared-secret check in `api/scan.js`.
- **Function duration.** A fresh (never-before-seen) URL can take up to ~60 seconds to analyze, since the function polls VirusTotal until it finishes. `vercel.json` sets `maxDuration: 60` for this function so it isn't cut off early.
- **Hobby plan is for personal, non-commercial use** per Vercel's terms — fine for a personal tool, but if this becomes something you charge for or run for others, move to a paid plan.
