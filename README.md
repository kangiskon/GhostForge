# GhostForge

Android-first phishing, scam, device and breach-awareness security suite (beta).

## Download an APK using only your Galaxy Tab S9+

Open **Actions** → **Build GhostForge Android APK** → latest successful run → **Artifacts** → **GhostForge-Debug-APK**. Extract and install the debug APK. No local Android SDK or computer required.

## Features in v0.4

| Area | Functionality | Limits |
| --- | --- | --- |
| Link investigator | URL inspection, known-threat feeds, manual link sharing and QR scans | Google Web Risk needs API key and hosted backend |
| DNS Guard | Optional DNS-only local VPN; Cloudflare Families anti-malware/phishing DNS plus custom blocklist | Not HTTPS-content interception; other VPN/Private DNS conflicts possible |
| APK inspector | User-selected APK hashes, manifest permission warnings, vetted malicious hash matching | Heuristics and known hashes aren't comprehensive antivirus |
| Scam investigator | Rule-based explanations and opt-in AI-generated guidance | Hosted API and optional AI key required; never claims 'safe' |
| Screenshot checks | On-device OCR of an explicitly chosen screenshot | User must review and choose to submit extracted text |
| Device audit | Screen lock, security-patch age and USB debugging checks | Cannot attest Play Protect or detect every compromise |
| Breach monitoring | Verified email address, licensed HIBP account check, scheduled opt-in notification checks | Requires SMTP and HIBP licensing; sessions expire |
| Account and devices | Verified-email identity, random-ID device registration and removal | Requires hosted SMTP/API; 30-day sessions |
| Family management | Up to five verified members, owner-only single-use invites and removal | Does not itself grant paid benefits |
| Privacy and scan history | Encrypted local hostname/verdict/timestamp history, deletion | Does not store full submitted URLs, scam texts or APK contents |
| Google Play subscriptions | Product queries, purchase/restore UI and server-side Google verification | Disabled until Play Console products, service account and Play distributed test build |

### Backend
\`backend/\` — FastAPI. Start with \`docker compose up -d --build\` after setting required secrets on the server. It binds to **127.0.0.1:8088** by default: configure a separate reverse proxy with HTTPS, rate limiting and authentication safeguards before making it accessible externally.

**Do not put passwords or API keys into GitHub code.** Never paste secrets into chat. Store server secrets only on a trusted host; use GitHub Actions secrets solely for build-related credentials if needed.

See [deployment and security](docs/DEPLOYMENT-SECURITY.md), [account/billing setup](docs/ACCOUNT-BILLING-SETUP.md) and [privacy draft](docs/PRIVACY-POLICY-DRAFT.md).

### What is not ready
This is **not** a production Guardio equivalent. Real malware engine validation, signed Play Store release, live paid subscriptions, independently audited family/account infrastructure, industrial threat intelligence, independent security audits, and store-policy approval are outstanding. DNS filtering should be tested on a secondary device before being relied upon.

Backend CI tests and Gradle debug APK compilation run on GitHub Actions for every push and pull request.
