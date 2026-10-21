'use strict';
const crypto = require('crypto');
const { cleanHost } = require('./probe');

const esc = s => String(s == null ? '' : s);
const num = (v, d) => { const n = parseInt(v, 10); return n > 0 && n < 65536 ? n : d; };

function generate(o = {}) {
  const bug = cleanHost(o.host) || 'bug.example.com';
  const server = cleanHost(o.server) || (/^[\d.]+$/.test(esc(o.server).trim()) ? esc(o.server).trim() : 'YOUR_SERVER');
  const port = num(o.port, 443);
  const wsPath = (esc(o.path).trim() || '/').replace(/[\r\n\s]/g, '');
  const uuid = /^[0-9a-f-]{36}$/i.test(esc(o.uuid)) ? o.uuid : 'YOUR-UUID';
  const pass = esc(o.password).replace(/[\r\n\s]/g, '') || 'YOUR_PASSWORD';
  const name = encodeURIComponent(esc(o.name).trim() || `MoonRadar-${bug}`);

  const payloads = [
    {
      name: 'WebSocket upgrade',
      text: `GET ${wsPath} HTTP/1.1[crlf]Host: ${bug}[crlf]Upgrade: websocket[crlf][crlf]`,
      note: 'Most common payload. Host header carries the bug host.'
    },
    {
      name: 'CONNECT with Host header',
      text: `CONNECT [host_port] [protocol][crlf]Host: ${bug}[crlf][crlf]`,
      note: 'Direct CONNECT; the carrier sees the bug host in the Host header.'
    },
    {
      name: 'Split: decoy GET, then CONNECT',
      text: `GET http://${bug}/ HTTP/1.1[crlf]Host: ${bug}[crlf][crlf][split]CONNECT [host_port] [protocol][crlf][crlf]`,
      note: 'First request looks like normal browsing to the bug host.'
    },
    {
      name: 'X-Online-Host headers',
      text: `CONNECT [host_port] [protocol][crlf]Host: [host][crlf]X-Online-Host: ${bug}[crlf]X-Forward-Host: ${bug}[crlf][crlf]`,
      note: 'Some carrier gateways honour these headers for billing.'
    },
    {
      name: 'Referer injection',
      text: `GET ${wsPath} HTTP/1.1[crlf]Host: [host][crlf]Referer: http://${bug}/[crlf]Upgrade: websocket[crlf][crlf]`,
      note: 'Bug host appears in Referer instead of Host.'
    },
    {
      name: 'Authority trick',
      text: `CONNECT [host_port]@${bug} [protocol][crlf][crlf]`,
      note: 'Behaviour varies a lot between carriers. Try last.'
    },
    {
      name: 'Delayed split',
      text: `GET / HTTP/1.1[crlf]Host: ${bug}[crlf][crlf][delay_split]CONNECT [host_port] [protocol][crlf][crlf]`,
      note: 'Same as split, with a delay between the two parts.'
    }
  ];

  const sniSteps = [
    'Tunnel type: SSH + SSL/TLS (or Xray/V2Ray with TLS)',
    `Server: ${server}`,
    `Port: ${port}`,
    `SNI / Server name: ${bug}`,
    'Payload: leave empty in SNI mode',
    'Tick "Use SNI" and turn off certificate verification if your server uses a self-signed cert'
  ].join('\n');

  const vless = `vless://${uuid}@${server}:${port}?encryption=none&security=tls&sni=${bug}&fp=chrome&type=ws&host=${bug}&path=${encodeURIComponent(wsPath)}#${name}`;
  const trojan = `trojan://${pass}@${server}:${port}?security=tls&sni=${bug}&type=ws&host=${bug}&path=${encodeURIComponent(wsPath)}#${name}`;
  const vmessObj = { v: '2', ps: decodeURIComponent(name), add: server, port: String(port), id: uuid, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: bug, path: wsPath, tls: 'tls', sni: bug };
  const vmess = 'vmess://' + Buffer.from(JSON.stringify(vmessObj)).toString('base64');
  const xray = JSON.stringify({
    outbounds: [{
      protocol: 'vless',
      settings: { vnext: [{ address: server, port, users: [{ id: uuid, encryption: 'none' }] }] },
      streamSettings: {
        network: 'ws', security: 'tls',
        tlsSettings: { serverName: bug, fingerprint: 'chrome', allowInsecure: false },
        wsSettings: { path: wsPath, headers: { Host: bug } }
      }
    }]
  }, null, 2);
  const stunnel = [
    '[ssh-sni]',
    'client = yes',
    'accept = 127.0.0.1:8443',
    `connect = ${server}:${port}`,
    `sni = ${bug}`,
    'verify = 0'
  ].join('\n');

  return {
    host: bug,
    payloads,
    configs: [
      { name: 'SNI setup (HTTP Injector / HA Tunnel)', text: sniSteps },
      { name: 'VLESS + WS + TLS link', text: vless },
      { name: 'VMess + WS + TLS link', text: vmess },
      { name: 'Trojan + WS + TLS link', text: trojan },
      { name: 'Xray outbound JSON', text: xray },
      { name: 'stunnel.conf', text: stunnel }
    ]
  };
}

function newUuid() { return crypto.randomUUID(); }

module.exports = { generate, newUuid };
