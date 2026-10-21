'use strict';
// Candidate root domains per country. These are STARTING POINTS only: the scanner expands them
// (subdomains, crawled asset hosts) and tests every result. Add your own zero-rated sites in the admin panel.

const COUNTRIES = {
  ZW: 'Zimbabwe', ZA: 'South Africa', KE: 'Kenya', NG: 'Nigeria', ZM: 'Zambia', TZ: 'Tanzania',
  UG: 'Uganda', GH: 'Ghana', MW: 'Malawi', MZ: 'Mozambique', BW: 'Botswana', NA: 'Namibia',
  RW: 'Rwanda', ET: 'Ethiopia', EG: 'Egypt', MA: 'Morocco', IN: 'India', ID: 'Indonesia',
  PH: 'Philippines', PK: 'Pakistan', BD: 'Bangladesh', BR: 'Brazil', MX: 'Mexico', GLOBAL: 'Global'
};

const CARRIERS = {
  ZW: ['Econet', 'NetOne', 'Telecel', 'TelOne'],
  ZA: ['Vodacom', 'MTN', 'Telkom', 'Cell C'],
  KE: ['Safaricom', 'Airtel', 'Telkom'],
  NG: ['MTN', 'Airtel', 'Glo', '9mobile'],
  ZM: ['Airtel', 'MTN', 'Zamtel'],
  TZ: ['Vodacom', 'Airtel', 'Tigo', 'Halotel'],
  UG: ['MTN', 'Airtel'],
  GH: ['MTN', 'Vodafone', 'AirtelTigo'],
  MW: ['Airtel', 'TNM'],
  MZ: ['Vodacom', 'Movitel', 'mCel'],
  BW: ['Mascom', 'Orange', 'BTC'],
  IN: ['Jio', 'Airtel', 'Vi', 'BSNL'],
  ID: ['Telkomsel', 'XL', 'Indosat', 'Tri'],
  PH: ['Globe', 'Smart']
};

const SEED_MAP = {
  ZW: { domains: [
    ['econet.co.zw', ['Econet']], ['ecocash.co.zw', ['Econet']], ['netone.co.zw', ['NetOne']],
    ['onemoney.co.zw', ['NetOne']], ['telecel.co.zw', ['Telecel']], ['telone.co.zw', ['TelOne']],
    ['zol.co.zw', []], ['liquid.tech', []], ['zimra.co.zw', []], ['potraz.gov.zw', []],
    ['zesa.co.zw', []], ['zbc.co.zw', []], ['herald.co.zw', []], ['cbz.co.zw', []],
    ['zimswitch.co.zw', []], ['ecosure.co.zw', ['Econet']]
  ] },
  ZA: { domains: [['vodacom.co.za', ['Vodacom']], ['mtn.co.za', ['MTN']], ['telkom.co.za', ['Telkom']], ['cellc.co.za', ['Cell C']], ['gov.za', []]] },
  KE: { domains: [['safaricom.co.ke', ['Safaricom']], ['airtel.co.ke', ['Airtel']], ['telkom.co.ke', ['Telkom']], ['ecitizen.go.ke', []], ['kra.go.ke', []]] },
  NG: { domains: [['mtn.ng', ['MTN']], ['airtel.com.ng', ['Airtel']], ['gloworld.com', ['Glo']], ['9mobile.com.ng', ['9mobile']]] },
  ZM: { domains: [['airtel.co.zm', ['Airtel']], ['mtn.zm', ['MTN']], ['zamtel.zm', ['Zamtel']]] },
  TZ: { domains: [['vodacom.co.tz', ['Vodacom']], ['airtel.co.tz', ['Airtel']], ['tigo.co.tz', ['Tigo']], ['halotel.co.tz', ['Halotel']]] },
  UG: { domains: [['mtn.co.ug', ['MTN']], ['airtel.co.ug', ['Airtel']]] },
  GH: { domains: [['mtn.com.gh', ['MTN']], ['vodafone.com.gh', ['Vodafone']], ['at.com.gh', ['AirtelTigo']]] },
  MW: { domains: [['airtel.mw', ['Airtel']], ['tnm.co.mw', ['TNM']]] },
  MZ: { domains: [['vodacom.co.mz', ['Vodacom']], ['movitel.co.mz', ['Movitel']]] },
  BW: { domains: [['mascom.bw', ['Mascom']], ['orange.co.bw', ['Orange']], ['btc.bw', ['BTC']]] },
  IN: { domains: [['jio.com', ['Jio']], ['airtel.in', ['Airtel']], ['myvi.in', ['Vi']], ['bsnl.co.in', ['BSNL']]] },
  ID: { domains: [['telkomsel.com', ['Telkomsel']], ['xl.co.id', ['XL']], ['indosatooredoo.com', ['Indosat']], ['tri.co.id', ['Tri']]] },
  PH: { domains: [['globe.com.ph', ['Globe']], ['smart.com.ph', ['Smart']]] },
  GLOBAL: { domains: [
    ['facebook.com', []], ['fbcdn.net', []], ['whatsapp.com', []], ['whatsapp.net', []], ['instagram.com', []],
    ['wikipedia.org', []], ['wikimedia.org', []], ['internet.org', []], ['freebasics.com', []],
    ['unicef.org', []], ['who.int', []], ['khanacademy.org', []], ['telegram.org', []],
    ['cloudflare.com', []], ['speedtest.net', []]
  ] }
};

const CCTLD = {
  zw: 'ZW', za: 'ZA', ke: 'KE', ng: 'NG', zm: 'ZM', tz: 'TZ', ug: 'UG', gh: 'GH', mw: 'MW', mz: 'MZ',
  bw: 'BW', na: 'NA', rw: 'RW', et: 'ET', eg: 'EG', ma: 'MA', in: 'IN', id: 'ID', ph: 'PH', pk: 'PK',
  bd: 'BD', br: 'BR', mx: 'MX'
};

function seedSources() {
  const out = [];
  for (const [country, v] of Object.entries(SEED_MAP)) {
    for (const [domain, carriers] of v.domains) {
      out.push({ domain, country, carriers, kind: 'seed', deep: false, enabled: true });
    }
  }
  return out;
}

function inferCountry(host, given) {
  if (host.endsWith('.zw')) return 'ZW';
  if (given && given !== 'GLOBAL') return given;
  const tld = host.split('.').pop();
  return CCTLD[tld] || given || 'GLOBAL';
}

const WORDLIST = ('www mail m mobile app apps api cdn static assets img images media portal selfservice self my account accounts ' +
  'login auth sso secure pay payments shop store web wap free zero data dev test stage staging beta admin support help care billing ' +
  'vpn proxy gw gateway ns1 ns2 smtp pop imap webmail ftp cloud drive docs download downloads dl update updates upload video videos ' +
  'stream live tv radio news blog forum community learn edu elearning lms moodle health careers jobs hr erp crm intranet remote mx ' +
  'relay edge origin lb graph connect id identity oauth ussd sms bulksms recharge topup airtime wallet money bank ebanking ' +
  'mobilebanking track status monitor search go link cms content files file music games game appstore play ' +
  'online digital ecommerce checkout cart webservices ws services mobi touch lite fast speed').split(/\s+/);

module.exports = { COUNTRIES, CARRIERS, CCTLD, seedSources, inferCountry, WORDLIST };
