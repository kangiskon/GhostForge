# GhostForge

GhostForge is an experimental Android phishing and link-reputation scanner. It is **not** an antivirus or always-on device protection app.

## Build on a Samsung Galaxy Tab S9+

Use the **Actions** tab in this GitHub repository. Every change to `main` starts an Android debug APK build. When the workflow succeeds, open its run, download `GhostForge-Debug-APK`, extract the ZIP, and install the APK on your tablet (approve install from that source if prompted).

The Android application source lives in `android/`; the optional Python scanner service lives in `backend/`. The APK is a debug/test build, not Google Play production-ready.

**Important:** The mobile app needs a reachable HTTPS GhostForge backend to perform real reputation lookups. The default endpoint is a placeholder. The backend uses optional commercial Web Risk credentials and must be securely hosted before use with real users. No submitted website is visited by the scanner. Never upload secrets to the repository.
