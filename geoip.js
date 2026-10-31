// Grobe Standortbestimmung einer IP-Adresse (Land/Stadt) über einen GeoIP-Dienst.
//
// Zweck in diesem Projekt: Jeder Nutzer sieht die ungefähre Region der letzten Anmeldungen
// an SEIN EIGENES Konto – wie eine Login-Warnung. Es geht ausdrücklich nicht darum,
// den Standort anderer Personen zu ermitteln.
//
// Hinweise:
// - GeoIP ist ungenau: es zeigt meist die Region des Internetanbieters/Knotens, nicht die
//   genaue Adresse. VPN und Mobilfunk verfälschen das Ergebnis stark.
// - Standard-Dienst: ip-api.com (kostenlos, keine Anmeldung, HTTP). Per Umgebungsvariable
//   GEOIP_URL austauschbar ({ip} wird ersetzt), z. B. gegen einen bezahlten HTTPS-Dienst.
// - Private/lokale Adressen werden ohne Anfrage als „lokales Netzwerk“ gemeldet.

const http = require('http');
const https = require('https');

const GEOIP_URL = process.env.GEOIP_URL || 'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,query&lang=de';
const cache = new Map(); // ip -> { region, ts }
const CACHE_MS = 24 * 60 * 60 * 1000;

function normalizeIp(ip) {
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) return ip.slice(7); // IPv4-in-IPv6
  return ip;
}
function isPrivate(ip) {
  return !ip || ip === '::1' || ip === '127.0.0.1' ||
    /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^169\.254\./.test(ip) || /^f[cd]/i.test(ip) || /^fe80/i.test(ip);
}
// IP anonymisiert für die Anzeige: letztes Oktett bzw. Suffix entfernt.
function maskIp(ip) {
  if (ip.includes('.')) return ip.replace(/\.\d+$/, '.x');
  if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':') + '::x';
  return ip;
}

function fetchJson(url) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: 4000, headers: { 'User-Agent': 'krypto-messenger' } }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

// Liefert { region, ip } – region ist ein menschenlesbarer String.
async function locate(rawIp) {
  const ip = normalizeIp(rawIp);
  const maskedIp = maskIp(ip);
  if (isPrivate(ip)) return { region: 'lokales Netzwerk', ip: maskedIp };

  const hit = cache.get(ip);
  if (hit && Date.now() - hit.ts < CACHE_MS) return { region: hit.region, ip: maskedIp };

  const j = await fetchJson(GEOIP_URL.replace('{ip}', encodeURIComponent(ip)));
  let region = 'unbekannt';
  if (j && (j.status === 'success' || j.country)) {
    region = [j.city, j.regionName, j.country].filter(Boolean).join(', ') || 'unbekannt';
  }
  cache.set(ip, { region, ts: Date.now() });
  return { region, ip: maskedIp };
}

// Client-IP aus der Anfrage. Hinter einem Reverse-Proxy nur vertrauen, wenn TRUST_PROXY gesetzt ist.
function clientIp(req) {
  if (process.env.TRUST_PROXY) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '';
}

module.exports = { locate, clientIp, maskIp };
