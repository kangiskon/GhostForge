# GhostForge v0.3.1 — DNS Guard repair and ghost status icon

The in-progress DNS beta now performs a direct HTTPS health check against the configured
Cloudflare Families DNS-over-HTTPS resolver *before* establishing the Android VPN.
If DNS is unreachable it reports the reason instead of activating a broken connection.

The VPN page provides:
- A **Check encrypted DNS connection** button to test upstream availability independently of VPN routing.
- Status text for VPN establishment, successful forwarded DNS queries, blocked queries, and resolver errors.
- A warning if Android Private DNS is set to a fixed provider and might bypass local filtering.
- Guidance to stop the VPN immediately if websites cannot load.

The GhostForge VPN foreground notification now uses a **white ghost** icon with
transparent background. Android's separate system-controlled VPN/key icon **cannot**
be replaced by an app. The notification has a tap-to-open shortcut and a Stop action.

## What is not yet guaranteed

The VPN is a limited proof of concept. It handles IPv4 UDP DNS requests using the Android
virtual DNS server and Cloudflare Families DNS-over-HTTPS, not TCP DNS, IPv6, app-specific
DoH/DoT or encrypted web content. The upstream test **does not** test end-to-end Android
VPN routing. Real Galaxy Tab S9+ testing is required before claiming reliable protection.

If it prevents browsing, turn DNS Guard off in GhostForge or disconnect via Samsung
Settings > Connections > More connection settings > VPN. Existing network connectivity
should return. The notification ghost may be hidden by Android's notification/status bar
configuration even while its notification is active.
