# CTF Atlas // Vercel + Automated Security Intelligence

CTF Atlas is an authenticated, self-contained CTF/cybersecurity learning portal. The portal teaches concepts directly in the site and includes learning paths, modules, tools, browser micro-labs, methodology, case studies, a glossary, and a local-practice/reference layer.

## Recommended free architecture

**GitHub repository + GitHub Actions + Vercel Hobby**

- **Vercel** hosts the authenticated site and serverless API.
- **GitHub Actions** runs the intelligence updater on a daily schedule and commits the normalized snapshot back to the repository.
- A new commit automatically triggers a fresh Vercel deployment, so the site's Live Intel view stays current without a database or always-on server.

GitHub documents that standard GitHub-hosted Actions runners are free in public repositories, and GitHub Free includes monthly Actions minutes for private repositories. GitHub Pages itself can host static sites on GitHub Free, but it cannot provide the custom server-side UID/password gate used by this project, so Pages is better as an unauthenticated static-hosting alternative. 

## What the updater does

`scripts/update-intel.mjs` is intentionally a **curated crawler/collector**, not an unrestricted internet spider. It fetches only explicitly allowlisted security sources, normalizes the results, maps each signal to a learning topic, and writes `data/live-intel.json`.

Current sources:

- CISA Known Exploited Vulnerabilities catalog
- NVD CVE 2.0 API
- OWASP Top 10 repository release feed
- OWASP Juice Shop release feed
- pwntools release feed

The resulting signal queue is used for discovery. It does **not** silently rewrite the core curriculum. That avoids allowing a compromised or misleading source to become trusted training content automatically.

The site exposes the snapshot through `/api/updates`, but only after the authenticated session has been validated.

## Vercel deployment

1. Upload this repository to GitHub.
2. In Vercel, import the repository.
3. Add these Environment Variables to the Vercel project:

```text
ATLAS_UID
ATLAS_PASSWORD
SESSION_SECRET
```

4. Deploy.

The UID/password are server-side Environment Variables and are not embedded in the client bundle.

## Automated refresh

The GitHub workflow is:

`.github/workflows/update-intel.yml`

It runs daily and can also be launched manually with **Run workflow**.

When new data is detected, it commits `data/live-intel.json`. Vercel then redeploys the updated site from the Git commit.

## Local development (optional)

The production target is hosted deployment, not local-only use. Local commands are provided only for validation/build work:

```bash
npm run check
npm run build
npm run update:intel
```

`npm run update:intel` needs outbound network access to collect the sources.

## Security design

- HTTP-only, Secure, SameSite=Strict session cookie
- HMAC-SHA256 signed session token
- No credential literals in browser source
- Protected `/portal` endpoint
- Protected `/api/updates` endpoint
- No arbitrary user-supplied URL crawler input
- Intelligence source allowlist
- Automated content is treated as a review queue, not authoritative curriculum

## Hosting alternatives

### Vercel
Best fit for this exact project because it supports serverless API routes, environment variables, and Git-based deployment. Vercel Cron also exists on all plans, with Hobby scheduled execution limited to once per day; however, this project uses GitHub Actions for persistence/versioning of the intelligence snapshot instead of trying to write files from a transient function.

### Cloudflare Pages + Functions
Also a strong free option. Cloudflare's current Pages Free plan includes static assets with free/unlimited static requests, and Functions use the Workers free quota. You would keep the same GitHub Actions updater and port the small auth/API layer to Pages Functions.

### Netlify
Easy Git-based hosting with serverless functions and a current Free plan. It can host the same general architecture, although the deployment files in this ZIP are Vercel-specific.

### GitHub Pages
Extremely easy for a public, static, unauthenticated version and works naturally with GitHub Actions. It is **not** suitable for the requested custom UID/password protection because Pages is static hosting.

## Why not a fully unrestricted crawler?

A security-education site should not blindly ingest arbitrary web pages every day. That can introduce malicious content, duplicated reporting, low-quality claims, prompt-injection-like text, or content that changes without notice. A source allowlist + normalization + topic detection + review queue is a safer benchmark design.
