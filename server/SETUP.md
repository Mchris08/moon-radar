# Tunnel server for HA Tunnel (SSH over TLS)

HA Tunnel logs in to an SSH server. A bug host only gets you past the carrier, so you need a server of your own.
This script turns a small rented Linux server into one.

## 1. Rent a server
- Ubuntu 22.04 or 24.04, 1 GB RAM, a public IPv4 address.
- Pick a location close to you (Johannesburg or Europe). Check the provider's terms allow SSH tunnelling.
- Your traffic goes through this server, so only use one you control.

## 2. Log in to it
From Termux:

    pkg install openssh
    ssh root@YOUR_SERVER_IP

(Or use the provider's web console.)

## 3. Run the script
If your GitHub repo is public:

    curl -fsSL https://raw.githubusercontent.com/Mchris08/moon-radar/main/server/setup-tunnel.sh -o setup.sh
    bash setup.sh

Otherwise paste the file in with `nano setup.sh`, then `bash setup.sh`.

It installs stunnel and fail2ban, creates a tunnel-only user, accepts SSH over TLS on port 443, and prints the settings.

## 4. HA Tunnel
Create a new config with:
- Tunnel type: SSH, with SSL/TLS (SNI) mode
- Server: the IP the script printed
- Port: 443
- Username and password: as printed
- SNI: a working bug host from Moon Radar, tested on your own carrier
- Payload: empty

Labels differ a little between app versions.

## If it does not connect
- On the server: `systemctl status moon-stunnel` and `ss -ltnp | grep 443`
- Allow TCP 443 in the provider's firewall panel if it has one.
- In Moon Radar: Tools, SNI check, enter your server and the bug host, tap Check server.
- Try the connection on Wi-Fi with no bug host. If that fails too, the problem is the server, not the host.
- If the app rejects a user with no shell, run `usermod -s /bin/bash USERNAME` on the server and try again.

More users: `bash setup.sh anothername`
