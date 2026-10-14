# GhostForge

Android-first phishing, scam, device and breach-awareness security suite (beta).

## Download an APK using only your Galaxy Tab S9+

Open **Actions** → **Build GhostForge Android APK** → latest successful run → **Artifacts** → **GhostForge-Debug-APK**. Extract and install the debug APK. No local Android SDK or computer required.

## Features in v0.9.0

| Area | Functionality | Limits |
| --- | --- | --- |
| Link investigator | Offline URL warning-sign checks, QR scans, sharing, optional live threat lookups | Offline results never mean safe; Google Web Risk requires a hosted backend |
| Licensed stealer-log intelligence | Verified-email checks against HIBP stealerLogsByEmail returning affected website domains | Requires HIBP Pro API key and verified ownership of email domain; no credential dumps or universal dark-web crawling |
| Authorized automatic opt-out emails | Verified users may consent to SMTP submission of a standardized broker deletion request to a domain-matched privacy mailbox | This submits requests only; SMTP acceptance does not mean a third party deleted data |
| Optery partner API readiness | Securely checks Optery for Business API credential/plan connectivity | Actual member/paid subscription onboarding and automatic Optery removal jobs require partner provisioning |
| Privacy Shield | User-controlled public exposure search links; HIBP breach checks for verified email; locally AES-GCM encrypted deletion cases; opt-out request drafts and manual response tracker | No universal dark-web crawler; no automatic site takedown or deletion guarantees; breach API requires SMTP and paid HIBP key |
| QR Safety Review | QR codes are decoded as inert text and inspected before any browser option is shown; suspicious or unsupported QR contents cannot be opened from GhostForge | No scanner can prove safety; live reputation checks need the configured HTTPS API and a licensed threat intelligence key |
| Phone Number Trace | User-entered offline phone number validation, numbering-plan country/region, assigned line type and NANP area prefix, optional user-initiated web search for public scam reports | Not owner identity, live location, current carrier, confirmed spam score, or active-line check; caller ID can be spoofed |
| Webpage Inspector | Explicit opt-in HTTPS HTML fetch, no scripts, local parsing of forms, redirects, misleading links and scam wording | Only first static HTML (192 KiB max), no cookies, no redirects; does not inspect other apps |
| Encrypted DNS Audit | Shows system Private DNS settings and documents DoH/DoT bypass limitations | Cannot decrypt, detect all apps' encrypted DNS, or inspect other apps' browsing |
| DNS Guard | Optional DNS-only local VPN; Cloudflare Families anti-malware/phishing DNS plus custom blocklist | Not HTTPS-content interception; other VPN/Private DNS conflicts possible |
| APK inspector | User-selected APK hashes, manifest permission warnings, vetted malicious hash matching | Heuristics and known hashes aren't comprehensive antivirus |
| Scam investigator | Offline warning-sign analysis, screenshots and optional AI-generated guidance | Live AI requires a configured backend; never claims safe |
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

**Offline mode (v0.4.1):** GhostForge can assess obvious warning signs in links and pasted scam messages even without an HTTPS backend. Offline detection performs **no threat-feed lookup** and never declares a link or message safe. If a configured remote scanner fails, the app falls back to the same limited local checks.

### Webpage inspection privacy (v0.5.0)
Webpage inspection is disabled until the user checks an explicit consent box. The phone makes **one HTTPS request directly to the chosen public website**: the website may log the source IP and requested path. No JavaScript executes, no redirects are followed, no cookies are attached, no authentication is attempted, and HTML is not uploaded to GhostForge servers. Local/private IP addresses and hostnames are excluded at URL validation and connection-time DNS lookup. Only a limited initial HTML response (192 KiB) is read; images and scripts aren't fetched. Webpage results aren't stored in the history database. Never use this to scan private URLs, password-reset links, or pages that could trigger one-time actions.

Encrypted DNS Audit reads Android's Private DNS setting and displays known protection gaps; it does not intercept other apps' encrypted DNS queries. A tested full-tunnel VPN would be necessary for even limited endpoint metadata monitoring and cannot passively decrypt third-party HTTPS/DoH without the relevant keys and consent. Nothing Phone testing remains pending.

### Phone Number Trace privacy and limitations (v0.6.0)
Open **Phone Trace** and enter a phone number manually. Google libphonenumber processes international numbering-plan metadata **on-device**. No contacts, call logs, SMS history or GPS permissions are requested. GhostForge does not store the entered phone number or automatically upload it to a backend or third-party data broker. The optional "Search public scam reports" button is disabled until the user explicitly checks a disclosure; it then opens Google Search with the phone number as part of the search query, disclosing it to that search provider.

**Do not confuse a numbering-plan area code with a person's location.** Number portability, VoIP and spoofed caller ID make region and number type unreliable for identifying actual callers. A recognized number pattern is not a live-line validation and never means "safe." GhostForge does not reveal subscriber identity, private records, real-time GPS position, or current carrier.

### GhostForge v0.7 — Scan QR before opening
The QR scanner now decodes a QR payload without opening it or entering a website automatically. The **QR Safety Review** screen checks scheme, hostname, port, encoded controls, local URL warning signs, and—when a configured backend is available—online threat-intelligence responses. It never launches Wi-Fi setup, telephone, SMS, payment, app installation, intent: or javascript: payloads. Plain HTTP URLs, local/IP destinations, shortened links and URLs with suspicious formatting are blocked from its Open action. Confirmed malicious URLs are blocked. If no threat provider is configured or it cannot be reached, the verdict is **UNVERIFIED**, not SAFE; opening requires the user's explicit acknowledgement. If online lookup returns no listing, GhostForge states **NOT LISTED**, not safe, and still requires user acknowledgement. The result display does not open the QR destination or follow redirects by itself. A user may choose to inspect a validated public HTTPS page's limited initial HTML before opening it, with separate consent.

### PhoneInfoga-style OSINT search worksheet
The **Phone Trace** tab still analyzes the number on-device using libphonenumber. In addition, six local public-source search queries are prepared, grouped by scam/spam reports, general mentions, business listings, public discussions, public social mentions and public PDFs. This is **inspired by PhoneInfoga's link-generating Googlesearch scanner**, not a bundled PhoneInfoga runtime or access to commercial carrier APIs. Nothing is scraped in the background or uploaded until the user explicitly enables and selects a public search; that search sends the number to Google and possibly websites reached from the results. Search results may refer to reassigned numbers or unrelated individuals and do not establish an owner's identity or geographic location. No GPS, contact, call-log or SMS permissions.

### Privacy Shield v0.8 — exposure awareness and removal
Privacy Shield is an opt-in privacy workflow for your own (or authorized) personal information.
- Public web: locally prepares five indexed search links for an entered name, email or phone number. The user must attest to authority; no search is executed until they choose a link. The search provider receives the chosen query when opened. No automatic scraping or harvesting.
- Licensed breach intelligence: connects to the existing **verified-email** Have I Been Pwned breach check when a self-hosted HTTPS API, SMTP verification and HIBP API subscription are configured. Missing credentials return "not checked", not "clean". This is known breach intelligence, **not** comprehensive monitoring of every dark-web marketplace.
- Exposure tracker: stores only a public domain name, exposure category, status and timestamps. It drops personal data from profile URLs and does not save search terms, addresses, names, phone numbers or removal letters. A separate Android Keystore AES-256-GCM encrypted local vault can be deleted in the app; it has no account sync or cloud backup.
- Removal: creates an editable request email to a contact address the user independently checks. The app opens their email program and **never sends it by itself**. The user manually confirms sending, receipt, and verified removal. No website is marked removed on mere submission, and no response status is fabricated.
- Privacy: no new Android contacts, call-log, SMS, location or accessibility permissions; never require a password or one-time code from a listing site. The source code cannot remove copies from uncooperative sites.
- The existing Breaches tab can optionally schedule background checks (WorkManager, approximate) for the user's verified email. This is not continuous dark-web crawling.

**Do not upload sensitive identities or documents to random removal contacts.** Verify the official broker privacy contact and confirm any deletion claim independently. No test or implementation guarantees full removal from search caches, breaches or criminal forums.

### v0.9 licensed providers and opt-out automation
**HIBP stealer logs:** GhostForge can request stealer-log *website domains* for the currently verified account's email via the licensed HIBP Pro endpoint. The domain of the email must be verified by the HIBP subscriber and the server must hold `HIBP_API_KEY`. Missing license, domain authorization or network error means NOT CHECKED, never safe. No passwords or other victims' records are retrieved.

**Automated opt-out emails:** The verified account can authorize an individual standard deletion/suppression email to a privacy mailbox whose domain matches the broker domain entered by the user. SMTP credentials must be configured on the server. Max two submissions per verified account per 24h and one per broker per 30 days. The server stores a minimal SQLite audit (verified email, broker hostname, mailbox, timestamps and submission state). Requests are not sent on app launch; each requires consent. SMTP receipt **does not confirm deletion**. Users can delete their request history from GhostForge without canceling already sent email.

**Optery for Business:** The server can check `GET /v1/plans` with `OPTERY_API_KEY=sk_test-...` and `OPTERY_ENVIRONMENT=sandbox` (or a production `sk_live-...` key and production environment). This connectivity check **does not create a member or enroll them in a removal plan**. Actual automated broker scanning/removals require separate Optery business-account onboarding, subscriber consent, an active paid plan and provider status tracking.

The default backend URL `https://api.example.invalid` cannot perform licensed checks or SMTP submissions. Configure the existing GhostForge HTTPS backend, email verification and server-only keys. None of these are stored in the APK. Dark-web coverage is incomplete; no service can forcibly erase records on criminal marketplaces.
