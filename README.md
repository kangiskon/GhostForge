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
