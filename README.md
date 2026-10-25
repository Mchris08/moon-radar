# Moon Radar

SNI / bug-host scanner for VPN tunnelling. Zero dependencies: just Node.js 18+.

## Run it

Android (Termux):

    pkg install nodejs unzip
    unzip moon-radar.zip && cd radar
    termux-wake-lock
    node server.js

PC or VPS: `node server.js`. Then open http://localhost:8080 (or http://SERVER-IP:8080).

## Hidden admin

There is no Admin link on the public site. The admin screen exists only at a secret address, `/<ADMIN_PATH>` (for example `https://your-site.onrender.com/m-k3x9...`). Set it yourself with `ADMIN_PATH=your-secret-word`; if you don't, one is generated and printed on first start. Visitors on any other address see no admin UI, and the login endpoint answers 404 unless it is called from the secret address. You still need the password.

First start prints the admin password once. Set your own with `ADMIN_PASSWORD=...`, and change it later in Settings.
Other env vars: `PORT`, `BIND`, `DATA_DIR`, `TRUST_PROXY=1` (behind nginx/Cloudflare).

## What it does

- Discovers hosts: subdomains from certificate logs (crt.sh, Cert Spotter), Anubis, HackerTarget, optional DNS guessing, and a crawler that pulls every host a zero-rated site loads assets from.
- Tests each host: DNS, TLS handshake with that name as SNI (version, cipher, certificate, HTTP/2), HTTPS reply, port 80, WebSocket upgrade on 443 and 80, CDN detection.
- Scores strength 0-100 (handshake, latency, TLS 1.3, h2, certificate, port 80, and stability over the last 14 tests) and recommends tunnelling modes (SSL/SNI, VLESS/VMess/Trojan, WS+TLS, gRPC, Reality target, HTTP payload).
- Daily pipeline (default 03:00 device time): find new hosts, re-test everything, drop auto-found hosts that stayed down 14 days. If the device was off or offline at that hour it runs as soon as it is online.
- Failed tests retry once with a longer timeout. If the internet itself is down, hosts are left unchanged instead of being marked dead.
- Zimbabwe (ZW or any .zw name): working hosts land in Admin > Review. Nothing is public until you approve it. Approved hosts hide automatically while down and return when they recover. Other countries publish automatically when working.
- Tools: SNI sniffer (paste or upload a VPN config and it lists every SNI, Host header, payload host and server in it: share links, Xray/V2Ray/sing-box JSON, Clash YAML, OpenVPN, WireGuard, stunnel, HTTP payloads and base64 subscriptions; locked app exports are not opened), SNI check (reads a server's certificate and tests which names it answers to), subdomain finder, host checker, bulk host tester (paste a list, results stream in), DNS lookup (this device's DNS or Cloudflare/Google/Quad9), port checker, SNI sniffer (reads a server's certificate and tests which names it answers to), config converter (vless/vmess/trojan link to Xray, sing-box and Clash, with a bug-host swap), and a payload and config generator (HTTP Injector payloads, SNI setup, VLESS, VMess, Trojan, Xray JSON, stunnel).
- Admin: review queue with bulk approve/reject/unpublish, host manager, zero-rated site sources, IP range (CIDR) certificate scan, scan control with live progress and log, settings.
- Export published hosts as TXT, CSV or JSON.

## Zero-rating is decided by the carrier, not the host

A server can only prove a host is alive and TLS-capable. Whether it is free depends on your carrier. So:

1. In Admin > Settings set "Carrier this device is on" (e.g. Econet) and run Radar on that SIM's mobile data. Every result is stamped "Tested on Econet".
2. For the real test, turn on Zero-balance mode and run a scan on a SIM with no data. Only zero-rated hosts will connect.
3. Approve Zimbabwe hosts from those results.

You also need your own tunnel server (SSH, V2Ray or Xray). Radar builds the client side.

## Tests

    npm test

Covers the probe engine against a local TLS/h2/WebSocket target, scoring, the approval workflow, auth, rate limits, the offline guard and every UI view.

## Tunnel server

HA Tunnel and HTTP Injector log in to an SSH server, so a bug host alone gives no internet. `server/setup-tunnel.sh` sets up SSH over TLS (port 443) on a rented Ubuntu or Debian VPS and prints the app settings. Read `server/SETUP.md`.

## Cloud configs

Admin > Cloud hosts your VPN config at a private link (`/c/<token>`) that stops working when its timer runs out. Paste vless, vmess or trojan links (one per line) and/or an SSH profile (server, port, user, password, SNI, payload), then set how long it lasts (5 minutes to 365 days). Options: start the timer when an app first opens it, and limit how many times apps can open it. You can extend, revoke, restore or delete a link at any time.

- The link works as a subscription URL in v2rayNG, NekoBox, Hiddify and similar apps. It sends the expiry time in the standard `Subscription-Userinfo` header, which apps that support it show. `?f=raw`, `?f=clash`, `?f=singbox` and `?f=xray` give other formats.
- Opening the link in a browser shows a readable page. That does not start the timer or use up the open limit.
- Expired links answer "410 Gone". Old expired links are removed after 30 days.
- HTTP Injector's own cloud config format is encrypted and proprietary, so it is not produced here.
- Cloud configs are stored on the server and are not part of backups, because they hold your server logins. On a free host that restarts, they are lost.

## Contact tab and WhatsApp

The public site has a Contact tab and a floating WhatsApp button on every page. The tab lists three WhatsApp numbers. Tapping one opens a chat with a short message already written ("Hi, I'm a user from Moon Radar...").

Under it, "Suggest or upload working hosts" lets visitors enter hosts, country, carrier and the app and mode they tested with. WhatsApp then opens with a ready-made message listing the hosts (up to 40). After a Phone test, the "Suggest these on WhatsApp" button fills the form with the reachable hosts. Each host's detail sheet also has "Report on WhatsApp". Messages go through WhatsApp, not through this server.

To change the numbers, edit the `WHATSAPP` list near the top of `public/app.js` (digits only, with country code).

## Footer

Every public page ends with a site footer: about Moon Radar with the live host count and last test time, quick links, the three WhatsApp numbers, a short "How it works", an FAQ, and Disclaimer, Privacy and Terms of use sections that expand when tapped, plus the copyright line. The text lives in `renderFooter()` in `public/app.js`.
