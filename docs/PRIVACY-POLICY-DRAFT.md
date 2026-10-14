# GhostForge — Draft Privacy Policy (not yet published)

**Draft date:** October 12, 2026

GhostForge is an experimental Android security tool from an independent developer. This draft must be reviewed and published at a stable HTTPS URL, with the operator's legal name, mailing address, contact address, and jurisdiction inserted before public release.

## Data handling

**URL reputation checks.** When a user requests a URL scan, the link is sent to the GhostForge server configured in Settings; if Google Web Risk credentials are configured, a third-party lookup may occur. This could reveal website addresses, including sensitive query strings. GhostForge does not intentionally open the submitted website. Avoid including sensitive identifiers in links.

**DNS Guard.** The optional Android VPN routes only system DNS resolution requests through GhostForge. Hostnames in a local blocklist are blocked, while other DNS requests are forwarded to Cloudflare Families over HTTPS. Cloudflare receives queried hostnames and handles them under its applicable privacy policy. GhostForge does not decrypt HTTPS or see every webpage.

**APK file checks.** Selected APK files are inspected on the device for manifest permissions, package information and SHA-256 hashes. Only hashes may be transmitted to the configured backend; APK binaries are not automatically uploaded.

**Scam messages and screenshots.** The app extracts text from selected screenshots on the device. Selected text is sent to the configured backend only when a user taps Analyze. Optional AI mode sends this text to the configured AI API provider after a separate opt-in. Scam contents are not deliberately persisted to the GhostForge database; provider-side retention and processing are governed by the provider's terms and account configuration. Users should avoid sending sensitive passwords and tokens.

**Email breach checking.** Verification emails and associated one-time codes are used to establish ownership. The server stores the verified email address and hashed, expiring verification-session tokens in its SQLite database. Licensed Have I Been Pwned email-breach searches occur only on verified accounts. Session tokens on Android are encrypted using the Android Keystore. Users can revoke and delete their verification-session records from within the application.

**Background notifications.** If opted in, Android WorkManager periodically checks verified email breach status. Newly detected exposure can trigger notifications. Breach names are locally cached to avoid repeated alerts.

**App diagnostics.** The application reads selected device settings and Android security-patch metadata locally to offer recommendations. It does not use SMS inbox access, Accessibility scraping, or broad installed-app inventory access.

## Retention and deletion

The prototype's manual URL and scam scan history is in memory and is cleared when the app process ends. On-device email verification tokens can be deleted in the Breaches screen; successful deletion revokes server-side sessions. Server logs must be configured by the operator not to retain submitted URLs, scam content, or emails longer than needed for security. Uninstalling the app clears its local state, but does not automatically revoke server-side sessions; use the in-app delete action before uninstalling.

## Security and user rights

The service should use HTTPS, least-privilege secrets, verified SMTP, encrypted backups, infrastructure-level rate limits, and a documented security contact. No content should be sold for advertising. Users should be able to request access/deletion by contacting the operator, who must publish a support address.

**Operator identity:** [INSERT]
**Support email:** [INSERT]
**Deletion request URL:** [INSERT]
**Hosting region and applicable jurisdiction:** [INSERT]
**Third-party providers and terms:** [REVIEW AND INSERT]

This draft is not legal advice and cannot be used as an accurate public policy without verifying the final system behavior and operator details.


## Privacy Shield (v0.8 beta)
The optional Privacy Shield prepares searches of your own information using Google Search links. Search text is not persisted or submitted until the user chooses an external search. Google and subsequently visited sites may see the query. Licensed breach checks use the existing verified-email API and are available only with a configured backend, SMTP provider, and HIBP API key. The app does not scrape hidden services. Public exposure case records consist only of domain, exposure category, status and timestamps, encrypted on device using Android Keystore AES-GCM. Account/device deletion does not automatically erase the separately stored local Privacy Shield cases; users can delete them in Privacy Shield or by uninstalling the app. Removal letters are generated in memory and opened in an email app at the user's direction; they are never auto-sent or stored by GhostForge. The app cannot promise that a third party will comply with or permanently remove a listing. Case statuses are based on user reports, not independently verified by GhostForge.


## Privacy Shield licensed provider integrations (v0.9 beta)
The optional HIBP Pro stealer-log lookup requires user consent for an already verified email and sends it only to the licensed provider. Status reflects unavailable or unauthorized plans; successful calls return only website domains, no stolen passwords. The automated opt-out email uses the verified email in Reply-To and sends a fixed deletion-request text to a domain-matched privacy mailbox chosen and authorized by the user. GhostForge server maintains a minimal per-user record of the website, verified owner email, recipient, submitted status and timestamps; deletion of those logs cannot recall sent emails. A reported SMTP submission does not mean a third party removed data. Optery partner connection tests do not submit member personal data or enroll subscriptions and are inactive until business-account provisioning. SMTP and provider API keys remain server-side.
