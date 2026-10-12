# GhostForge v0.3 — Deployment and verification

This repository includes Android debug builds and a FastAPI proof-of-concept server, **not a production-ready consumer antivirus**.

## Android features
- User-consented DNS-only split-tunnel VPN with Cloudflare Families malware/phishing DNS-over-HTTPS and a custom hostname blocklist.
- Manual URL checks, QR decoding, and Android share-to-scan.
- User-selected APK archive/package inspection; SHA-256 checks against a server-configured bad-hash list; never upload APK bytes.
- Android device settings audit: screen lock, patch age, and developer USB debugging state.
- Scam text investigator: rule-based warning signs plus **optional** AI narrative analysis. Screenshot images are OCR-extracted on device, and only reviewed text is submitted.
- Verified email breach lookup plus opt-in periodic checks using Android WorkManager. Android may delay or skip scheduled work; the monitor only works when the backend is available and an email session is valid.

## Server deployment
1. Use Ubuntu, Docker, a trusted HTTPS reverse proxy, TLS, service logging/redaction, encrypted backup, and a firewall.
2. In a **server-only**, private environment file, set:
   - GHOSTFORGE_AUTH_SECRET: random 32+ character value, never check into Git.
   - SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_USER, SMTP_PASSWORD: SMTP mail delivery for verified-email codes.
   - HIBP_API_KEY: a licensed Have I Been Pwned API key for breached account lookups.
   - OPENAI_API_KEY: optional; if set, opt-in scam text goes to the AI provider.
   - OPENAI_SCAM_MODEL: optional, supported model name.
   - WEB_RISK_API_KEY: optional commercial malicious-URL feed.
   - BLOCKED_DOMAINS and KNOWN_BAD_APK_SHA256: vetted security threat lists, not arbitrary user-supplied data.
3. Run \`docker compose up -d --build\`. Scanner binds only to localhost port 8088; reverse proxy and HTTPS are separate deployments.
4. Configure Android app Settings with your **HTTPS URL**. In an offline/unconfigured state, remote checks are explicitly unavailable or unverified.
5. Check /health, test a harmless sample link, request a verification code, confirm token replay protections and deletion, then check the licensed breach provider.
6. Before public use: implement infrastructure-level IP throttling/DoS protection, multi-instance sessions, encrypted database at rest, secrets rotation, backups, alert integrity and telemetry consent.

## Critical privacy boundaries
- Scam message analysis: content is sent to the GhostForge backend when tapped; it is then processed transiently. AI is off until the user explicitly opts in; AI mode sends the selected text to an external AI API. Do not paste passwords, private keys or other secrets.
- Breach monitoring: email ownership is verified with a one-time code before the paid HIBP account-breach service is called. The service stores a verified email plus expiring hashed session token in SQLite. The Android app stores its token using Android Keystore encryption. Users can delete verification records.
- APK inspection: file stays on-device; only SHA-256 may be sent to the configured reputation backend.
- DNS Guard: forwards hostname queries to Cloudflare Families using DNS-over-HTTPS; doesn't see HTTP page content. Android can use only one VPN per profile.
- No automated SMS inbox reading, notification listener, accessibility scraping, installed-app inventory, VPN interception of HTTPS content, or arbitrary traffic decryption.

## Prelaunch gates (not finished)
- Real Android phone/tablet device tests, DNS filtering compatibility tests on mobile/Wi-Fi/Private DNS, independent penetration test, and threat-evasion testing.
- Google Play policy declarations, special-use foreground service justification, VPN prominent disclosure, Data Safety, documented privacy policy and account deletion URL.
- Real licensed enterprise threat feeds, low-false-positive testing, incident response, code signing keystore and secure Play publishing.
- Google Play Billing product IDs, receipt/entitlement verification, cancellation/refunds, support policy.
- Commercial authentication infrastructure, durable audit logs with short retention, scalable DB, outbound email delivery, and customer support.
- Device / family account management: planned, **not shipped**.
