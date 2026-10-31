// Krypto-Messenger – Relay-Server
// Der Server sieht NUR verschlüsselte Umschläge. Klartext, Medien und Status
// werden ausschließlich im Browser ver- und entschlüsselt.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const geoip = require('./geoip');

const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const PUBLIC = path.join(__dirname, 'public');

// ---------- Persistenz ----------
let db = { users: {}, groups: {}, queue: {} };
try { db = { ...db, ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) }; } catch {}
let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => fs.writeFile(DATA_FILE, JSON.stringify(db), () => {}), 200);
}
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------- Statische Dateien ----------
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC, p));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(buf);
  });
});

// ---------- WebSocket ----------
const wss = new WebSocketServer({ server, maxPayload: 40 * 1024 * 1024 });
const online = new Map(); // name -> Set<ws>

const send = (ws, obj) => ws.readyState === 1 && ws.send(JSON.stringify(obj));
const toUser = (name, obj) => {
  const set = online.get(name);
  if (set && set.size) { set.forEach((ws) => send(ws, obj)); return true; }
  return false;
};
const broadcast = (obj) => online.forEach((set) => set.forEach((ws) => send(ws, obj)));
const publicUser = (name) => {
  const u = db.users[name];
  return u && { name, pub: u.pub, about: u.about || '', online: online.has(name), lastSeen: u.lastSeen };
};
function deliverOrQueue(name, obj) {
  if (!toUser(name, obj)) {
    (db.queue[name] ||= []).push(obj);
    save();
  }
}
const validName = (n) => typeof n === 'string' && /^[a-zA-Z0-9_.\-äöüÄÖÜß]{3,24}$/.test(n);

wss.on('connection', (ws, req) => {
  let me = null;
  const ip = geoip.clientIp(req);

  // Ungefähre Region dieser Anmeldung ermitteln und in der Login-Historie des Nutzers
  // ablegen (nur für den Nutzer selbst sichtbar). Blockiert die Anmeldung nicht.
  const recordLogin = async (name) => {
    try {
      const { region, ip: masked } = await geoip.locate(ip);
      const u = db.users[name];
      if (!u) return;
      u.logins = (u.logins || []);
      u.logins.unshift({ ts: Date.now(), region, ip: masked });
      u.logins = u.logins.slice(0, 10);
      save();
      send(ws, { t: 'logins', logins: u.logins });
    } catch {}
  };

  const login = (name) => {
    me = name;
    if (!online.has(name)) online.set(name, new Set());
    online.get(name).add(ws);
    const groups = Object.values(db.groups).filter((g) => g.members.includes(name));
    send(ws, { t: 'authed', name, groups, opkCount: db.users[name].opks?.length || 0, logins: db.users[name].logins || [] });
    const q = db.queue[name] || [];
    delete db.queue[name];
    save();
    q.forEach((m) => send(ws, m));
    broadcast({ t: 'presence', name, online: true });
    recordLogin(name);
  };

  ws.on('message', (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    if (m.t === 'register') {
      if (!validName(m.name)) return send(ws, { t: 'error', msg: 'Name: 3–24 Zeichen (Buchstaben, Zahlen, _ . -)' });
      if (db.users[m.name]) return send(ws, { t: 'error', msg: 'Name ist schon vergeben' });
      const k = m.keys;
      if (!k?.ik || !k.sigPub || !k.spk?.pub || !k.spk.sig || !Array.isArray(k.opks)) return send(ws, { t: 'error', msg: 'Schlüssel fehlen' });
      const token = crypto.randomBytes(32).toString('hex');
      db.users[m.name] = { pub: { ik: k.ik, sigPub: k.sigPub }, spk: k.spk, opks: k.opks.slice(0, 200),
        tokenHash: sha(token), lastSeen: Date.now(), about: 'Hey, ich nutze Krypto-Messenger!' };
      save();
      send(ws, { t: 'registered', name: m.name, token });
      return login(m.name);
    }
    if (m.t === 'auth') {
      const u = db.users[m.name];
      if (!u || u.tokenHash !== sha(String(m.token))) return send(ws, { t: 'autherror' });
      return login(m.name);
    }
    if (!me) return;

    switch (m.t) {
      case 'lookup': {
        const u = publicUser(m.name);
        return send(ws, u ? { t: 'user', ...u, rid: m.rid } : { t: 'nouser', name: m.name, rid: m.rid });
      }
      case 'bundle': {
        // Prekey-Bundle für den Sitzungsaufbau (X3DH). Jeder Einmal-Prekey wird nur einmal ausgegeben.
        const u = db.users[m.name];
        if (!u?.spk) return send(ws, { t: 'nobundle', rid: m.rid });
        const opk = u.opks.shift() || null;
        save();
        if (u.opks.length < 10) toUser(m.name, { t: 'prekeys_low', count: u.opks.length });
        return send(ws, { t: 'bundle', rid: m.rid, bundle: { ik: u.pub.ik, sigPub: u.pub.sigPub, spk: u.spk, opk } });
      }
      case 'prekeys': {
        const u = db.users[me];
        if (Array.isArray(m.opks)) { u.opks.push(...m.opks.slice(0, 100)); u.opks = u.opks.slice(-200); save(); }
        return;
      }
      case 'about': {
        db.users[me].about = String(m.about || '').slice(0, 140); save();
        return;
      }
      case 'send': {
        // m.envs: { empfänger: {iv, ct} } – pro Empfänger einzeln verschlüsselt
        const ts = Date.now();
        Object.entries(m.envs || {}).forEach(([to, env]) => {
          if (!db.users[to]) return;
          deliverOrQueue(to, { t: 'msg', from: me, id: m.id, ts, env });
        });
        return send(ws, { t: 'ack', id: m.id, ts });
      }
      case 'receipt': // {to, ids, state: delivered|read}
        if (db.users[m.to]) deliverOrQueue(m.to, { t: 'receipt', from: me, ids: m.ids, state: m.state });
        return;
      case 'typing':
        if (Array.isArray(m.to)) m.to.forEach((n) => toUser(n, { t: 'typing', from: me, chat: m.chat }));
        return;
      case 'group_create': {
        const members = [...new Set([me, ...(m.members || [])])].filter((n) => db.users[n]);
        const g = { id: crypto.randomUUID(), name: String(m.name || 'Gruppe').slice(0, 40), members, admin: me, created: Date.now() };
        db.groups[g.id] = g; save();
        members.forEach((n) => deliverOrQueue(n, { t: 'group', group: g }));
        return;
      }
      case 'group_leave': {
        const g = db.groups[m.id];
        if (!g) return;
        g.members = g.members.filter((n) => n !== me); save();
        [...g.members, me].forEach((n) => deliverOrQueue(n, { t: 'group', group: g }));
        return;
      }
    }
  });

  ws.on('close', () => {
    if (!me) return;
    const set = online.get(me);
    set?.delete(ws);
    if (!set?.size) {
      online.delete(me);
      db.users[me].lastSeen = Date.now(); save();
      broadcast({ t: 'presence', name: me, online: false, lastSeen: db.users[me].lastSeen });
    }
  });
});

server.listen(PORT, () => console.log(`Krypto-Messenger läuft auf http://localhost:${PORT}`));
