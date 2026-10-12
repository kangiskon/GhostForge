# GhostForge v0.3.2 VPN startup and ghost notification

The previous DNS screen silently hid startup failures beneath the lower blocklist fields. The new screen displays status and startup errors next to the Start button, requests Android notification permission (required for the ghost status notification on Android 13+), requests Android VPN authorization, and checks preparation after the system prompt. The foreground service persists its progress and failures to app settings for debugging even after service shutdown. It also times out the startup UI if no VPN tunnel appears within 18 seconds.

Tap **Start DNS Guard**, approve notifications and the Android VPN dialog. Check **VPN status** and the **VPN error** message. If the VPN is connected but DNS is broken, turn it off from GhostForge or Samsung Settings immediately. The separate Android VPN/key indicator is system controlled. The ghost is only for the GhostForge notification, which may be hidden by notification settings or the status-bar icon limit.

The DNS packet-filter prototype still requires physical device validation. Successful compilation is not proof the VPN routes DNS queries on all Samsung Android versions.

## Essential VPN stability correction

Android VPN TUN descriptors are **non-blocking by default**. The original service used `FileInputStream.read()` as a blocking packet reader, so an empty incoming queue could be treated as an end-of-file and the service would close itself. The builder now calls `setBlocking(true)` and records unexpected read failures. Since this beta only filters IPv4 UDP DNS, it explicitly allows IPv6 traffic to bypass rather than blocking IPv6 connectivity. DNS-over-TLS and third-party DNS-over-HTTPS can still bypass filtering.
