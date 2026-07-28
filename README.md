# URL Threat Scanner

A VirusTotal-backed URL scanner. Visitors don't need their own API key — scanning
is powered by one VirusTotal API key configured **server-side only**, via an
environment variable.

## How it works

- **`POST /api/scan`** checks VirusTotal's cache first. If the URL is already
  known, it returns a full report in well under a second. If it's brand new,
  it kicks off a scan and returns immediately with an `analysisId` — it never
  makes the browser wait.
- **`GET /api/status`** is polled by the page every few seconds until that
  analysis finishes (usually 15–60s for a genuinely new URL). Each poll is a
  quick, independent request, so the UI stays responsive instead of hanging
  on one long request.
- Your VirusTotal key lives only in `process.env.VT_API_KEY`, read on the
  server. It is never sent to, or visible in, the browser.

## Local setup

```bash
npm install
cp .env.example .env
# edit .env and paste your VirusTotal API key into VT_API_KEY=
node server.js
```

Open **http://localhost:3000**.

Get a free key at [virustotal.com](https://www.virustotal.com/gui/join-us).
The free tier allows **~4 lookups/minute and 500/day** — see "About rate
limits" below, this matters a lot once the tool is public.

## Deploying to Vercel

1. Push this folder to a GitHub repo. **Do not** put your real API key in any
   committed file — `.env` is already git-ignored for this reason.
2. Go to [vercel.com/new](https://vercel.com/new) and import the repo (framework
   preset: "Other").
3. Before or after the first deploy, go to **Project → Settings →
   Environment Variables** and add:
   - Key: `VT_API_KEY`
   - Value: your VirusTotal API key
   - Environments: Production (and Preview/Development if you want those to work too)
4. Redeploy (Vercel → Deployments → ⋯ → Redeploy) so the function picks up the
   new environment variable.

You'll get a URL like `https://your-project.vercel.app`. No visitor ever needs
to enter or see the key — `api/scan.js` and `api/status.js` are the only code
that touches it, and both run server-side.

## About rate limits (read this before going public)

VirusTotal's **free public API key is capped at ~4 requests/minute and
500/day, for the key itself** — not per visitor. Once this key is shared by
everyone who uses your deployed tool, that ceiling applies to *all your
traffic combined*.

This project protects the key with two safeguards in `api/_lib.js`:

- **Global limiter** — refuses new *submissions* (not cached lookups) once
  ~4/min are in flight, returning a fast, clear 429 instead of letting
  VirusTotal itself reject the request later.
- **Per-IP limiter** — caps each visitor to 20 scans/hour, so one person
  can't burn through the whole shared quota.

Both are **in-memory**, meaning they reset on a serverless cold start and
aren't shared across multiple concurrent function instances. That's a
reasonable first line of defense for light-to-moderate traffic, but it is
*not* a hard guarantee at real scale. If you expect meaningful public
traffic:

- **Get a paid VirusTotal API tier** (higher quota — the real fix), or
- **Add a proper shared rate-limit store** like [Upstash Redis](https://upstash.com)
  or [Vercel KV](https://vercel.com/docs/storage/vercel-kv) — a few lines swapped
  into `_lib.js` in place of the in-memory `Map`/array, or
- Cache completed results in that same store so repeat scans of popular URLs
  never touch your VirusTotal quota at all.

Being upfront about this: a single free-tier key genuinely cannot support
heavy public traffic no matter how the code is written — that's a VirusTotal
account-tier limit, not a bug in this app.

## What it does

- **Scan one or more URLs** (one per line). Existing VirusTotal records are
  reused instantly; brand-new URLs are submitted and tracked to completion.
- **Full report per URL**: detection ratio, per-engine breakdown, community
  categories, reputation score, WHOIS record, final URL after redirects, and
  HTTP response code.
- **History**, saved in the visitor's own browser (`localStorage`) — never
  sent to the server.
- **Print / PDF export** per report via the browser's print dialog.
- Basic input validation blocks empty/malformed URLs and internal/loopback
  addresses before they ever reach VirusTotal.

## Security notes

- Never commit a real `.env` file — `.gitignore` already excludes it.
- If you rotate your VirusTotal key, just update the `VT_API_KEY` value in
  Vercel's dashboard and redeploy; nothing in the code needs to change.
- There's no login/auth on this app itself — anyone with the link can submit
  scans (bounded by the rate limiters above). Add your own auth in front of
  it (e.g. Vercel password protection on paid plans, or a simple shared-secret
  check) if you need to restrict access.
