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
