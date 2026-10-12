# GhostForge

Android security app prototype: a manual link investigator with QR scanning, Share-to-scan, optional Google Web Risk-backed reputation checks, and a private Python FastAPI backend.

**This is a development prototype, not an antivirus or always-on web protection.** It never claims an unverified website is safe.

## Build on Galaxy Tab S9+

1. Open **Actions** → **Build GhostForge Android APK** in this repository.
2. Open the latest run, then **Artifacts** → **GhostForge-Debug-APK**.
3. Extract the downloaded ZIP and install the APK on the Galaxy Tab S9+.

Each push to `main` triggers a new cloud APK build. A manual **Run workflow** option is also included. No computer or local Android SDK required.

## Live URL checks

The APK requires a real HTTPS backend URL, entered in **Settings**. The repository includes `backend/` for hosting separately on a trusted server. API calls are not available by default until you configure a server. The backend is not production-hardened (no authentication, request limits or audit controls). **Do not expose it publicly without adding security controls.**

Configure the commercial Google Web Risk API key as an environment variable **only on the backend**. No key belongs in an Android APK or repository. Until that service is available, the backend returns `unverified` or heuristic `suspicious`, not "safe".

## Status

- Android Studio Kotlin / Jetpack Compose project in `android/`
- Python FastAPI link scanner in `backend/`
- GitHub Actions debug APK build (unsigned for distribution, debug-signed for testing)
- Requires review and hardening before Play Store submission

## Version 0.2 experimental security modules

**DNS Guard:** User-initiated DNS-only split-tunnel Android VPN. The user must accept an in-app disclosure and Android's VPN prompt. GhostForge reads DNS hostname queries routed to its local virtual resolver, compares against a local list, and answers blocked names with NXDOMAIN. Non-blocked DNS queries are forwarded to Cloudflare Families malware/phishing filtering resolver using HTTPS (DNS-over-HTTPS). It neither inspects encrypted HTTP paths nor filters traffic that bypasses the system DNS resolver (such as app-specific DoH). The reserved **malware.test** demo domain is blocked locally by default; Cloudflare Families also blocks its currently known malware/phishing domain categories. Additional coverage requires a vetted backend blocklist or manually supplied domains. For commercial resale, review Cloudflare service terms and licensing. The system allows only one VPN per Android profile. The user can stop the foreground service at any time. Test carefully on a noncritical device; early TUN/DNS support may affect connectivity and is not production-ready.

**APK Inspector:** Uses Android's system document picker (no broad storage or installed-app inventory permissions), reads an APK locally (120 MB limit), computes its SHA-256 hash, inspects archive layout and package permissions, and optionally looks up the hash via HTTPS on your backend. An APK file is **not uploaded**. Unknown results never mean safe. This is *static triage*, not comprehensive malware detection.

**Backend feeds:** Set `BLOCKED_DOMAINS` to a comma/newline-separated list of vetted domains; set `KNOWN_BAD_APK_SHA256` to verified malicious 64-character SHA-256 values, comma or newline separated. Without these feeds, only demo DNS filtering and APK permission heuristics are available. The backend is proof-of-concept and must be secured (authentication, rate limits, TLS reverse proxy, logging controls) before publicly exposed.

Google Play distribution is not approved: the VPN functionality requires special declarations, prominent disclosure and privacy review. Use only the debug APK for testing. Do **not** market it as complete malware or identity protection.

## Test checklist

1. Install debug APK on Galaxy Tab S9+, grant VPN permission after reading the DNS disclosure, confirm notification is visible.
2. Confirm `malware.test` fails DNS resolution while a normal domain resolves; disconnect and confirm normal connectivity returns.
3. Confirm stopping DNS Guard disables the VPN. Try mobile and Wi-Fi networks and an existing VPN to check conflicts.
4. Inspect a known harmless test APK using the file picker; note the hash, permissions and **unknown reputation**.
5. Host the backend behind HTTPS, configure domain and SHA feeds, and verify known matching test values; test without a backend as well.
