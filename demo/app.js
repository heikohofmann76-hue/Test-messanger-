'use strict';
/* Krypto-Messenger – Client
 * Kryptografie: Signal-artiges Protokoll (X3DH + Double Ratchet) aus signal.js.
 *   - Identitäts- und Signaturschlüssel pro Gerät, privat und nicht exportierbar, nur in IndexedDB.
 *   - Forward Secrecy: jede Nachricht hat einen eigenen Schlüssel, alte werden verworfen.
 * Gruppen: Absender verschlüsselt die Nachricht einzeln für jedes Mitglied (Fan-out).
 * Der Server sieht nur Absender, Empfänger, Zeit und Chiffretext.
 */

// ---------------- IndexedDB ----------------
const idb = (() => {
  const kv = new Map(), msgs = new Map();
  const c = (v) => (v && typeof v === 'object' && !(v instanceof CryptoKey) ? structuredClone(v) : v);
  return {
    get: async (k) => kv.get(k), set: async (k, v) => { kv.set(k, v); },
    putMsg: async (m) => { msgs.set(m.id, c(m)); }, delMsg: async (id) => { msgs.delete(id); },
    getMsg: async (id) => c(msgs.get(id)), allMsgs: async () => [...msgs.values()].map(c),
  };
})();
const idbUnused = (() => {
  let dbp;
  const open = () => dbp ||= new Promise((res, rej) => {
    const r = indexedDB.open('krypto-messenger', 1);
    r.onupgradeneeded = () => {
      const d = r.result;
      d.createObjectStore('kv');
      d.createObjectStore('msgs', { keyPath: 'id' }).createIndex('chat', 'chat');
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  const tx = async (store, mode, fn) => {
    const d = await open();
    return new Promise((res, rej) => {
      const t = d.transaction(store, mode);
      const s = t.objectStore(store);
      const out = fn(s);
      t.oncomplete = () => res(out && 'result' in out ? out.result : out);
      t.onerror = () => rej(t.error);
    });
  };
  return {
    get: (k) => tx('kv', 'readonly', (s) => s.get(k)),
    set: (k, v) => tx('kv', 'readwrite', (s) => s.put(v, k)),
    putMsg: (m) => tx('msgs', 'readwrite', (s) => s.put(m)),
    delMsg: (id) => tx('msgs', 'readwrite', (s) => s.delete(id)),
    getMsg: (id) => tx('msgs', 'readonly', (s) => s.get(id)),
    allMsgs: () => tx('msgs', 'readonly', (s) => s.getAll()),
  };
})();

// ---------------- Krypto ----------------
// Die eigentliche Kryptografie (X3DH + Double Ratchet) steckt in signal.js.
// Hier liegt nur die Anbindung: Identität erzeugen, Prekeys nachfüllen, Sitzungen speichern.
const enc = new TextEncoder(), dec = new TextDecoder();
const toB64 = Signal.toB64, fromB64 = Signal.fromB64;

// Sitzungsspeicher: pro Kontakt eine Liste von Ratchet-Zuständen, in IndexedDB abgelegt.
const sessionStore = {
  async loadSessions(peer) { return (await idb.get('sess:' + peer)) || null; },
  async saveSessions(peer, list) { await idb.set('sess:' + peer, list); },
  async saveIdentity() { await idb.set('identity', S.identity); },
  async fetchBundle(peer) {
    return new Promise((res) => {
      const rid = uid(); S.pendingLookups[rid] = res;
      wsSend({ t: 'bundle', name: peer, rid });
      setTimeout(() => { if (S.pendingLookups[rid]) { delete S.pendingLookups[rid]; res(null); } }, 5000);
    });
  },
};
let ratchet = null; // Signal.createManager(...), nach dem Laden der Identität gesetzt

async function newIdentity() {
  const id = await Signal.createIdentity();
  const opks = await Signal.newOneTimePrekeys(id, 20);
  return { id, keys: { ...Signal.publicIdentity(id), spk: Signal.publicSpk(id), opks } };
}
async function topUpPrekeys(target = 20) {
  const have = Object.keys(S.identity.opks).length;
  if (have >= target) return;
  const opks = await Signal.newOneTimePrekeys(S.identity, target - have);
  await sessionStore.saveIdentity();
  wsSend({ t: 'prekeys', opks });
}
// Sicherheitsnummer aus beiden Identitätsschlüsseln (wie bei Signal „Safety Number“)
async function safetyNumber(myIk, theirIk) {
  const parts = [myIk, theirIk].sort().join('|');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-512', enc.encode(parts)));
  const out = [];
  for (let i = 0; i < 12; i++) out.push(String(((h[i * 3] << 16) | (h[i * 3 + 1] << 8) | h[i * 3 + 2]) % 100000).padStart(5, '0'));
  return out;
}

// ---------------- Zustand ----------------
const S = {
  name: null, token: null, identity: null,
  contacts: {},   // name -> {ik, about, online, lastSeen, keyChanged}
  groups: {},     // id -> group
  chats: {},      // chatId -> {id, type:'u'|'g', target, last, unread, typing}
  msgs: {},       // chatId -> [msg]
  statuses: [],   // {id, from, ts, kind, text, bg, data}
  seenStatus: {}, // id -> true
  current: null, replyTo: null, ws: null, tab: 'chats', pendingLookups: {},
};
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = () => crypto.randomUUID();
const COLORS = ['#e17076', '#7bc862', '#65aadd', '#a695e7', '#ee7aae', '#6ec9cb', '#faa774', '#0b8f6a'];
const colorOf = (s) => COLORS[[...s].reduce((a, c) => a + c.charCodeAt(0), 0) % COLORS.length];
const initials = (s) => s.slice(0, 2).toUpperCase();
const fmtTime = (ts) => new Date(ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
const fmtDay = (ts) => {
  const d = new Date(ts), t = new Date();
  const y = new Date(); y.setDate(t.getDate() - 1);
  if (d.toDateString() === t.toDateString()) return 'Heute';
  if (d.toDateString() === y.toDateString()) return 'Gestern';
  return d.toLocaleDateString('de-DE', { day: '2-digit', month: 'long', year: 'numeric' });
};
const fmtListTime = (ts) => {
  const d = new Date(ts), t = new Date();
  if (d.toDateString() === t.toDateString()) return fmtTime(ts);
  return (t - d < 6 * 864e5) ? d.toLocaleDateString('de-DE', { weekday: 'short' }) : d.toLocaleDateString('de-DE');
};
const lastSeenText = (c) => c?.online ? 'online' : c?.lastSeen ? `zuletzt online ${fmtDay(c.lastSeen).toLowerCase()} um ${fmtTime(c.lastSeen)}` : '';
function avatarHTML(name, { cls = '', online = false, group = false } = {}) {
  return `<div class="avatar ${cls}" style="background:${colorOf(name)}">${group ? '👥' : esc(initials(name))}${online ? '<span class="on"></span>' : ''}</div>`;
}
function toast(t) { const el = $('#toast'); el.textContent = t; el.classList.remove('hidden'); clearTimeout(toast.t); toast.t = setTimeout(() => el.classList.add('hidden'), 2600); }
async function persist() {
  await idb.set('contacts', S.contacts);
  await idb.set('groups', S.groups);
  await idb.set('chats', Object.fromEntries(Object.entries(S.chats).map(([k, v]) => [k, { ...v, typing: false }])));
  await idb.set('statuses', S.statuses);
  await idb.set('seenStatus', S.seenStatus);
}

// ---------------- Netzwerk ----------------
function connect() {
  const ws = parent.DemoServer.connect((data) => ws.onmessage?.({ data }));
  S.ws = ws;
  ws.onopen = () => {
    if (S.token) ws.send(JSON.stringify({ t: 'auth', name: S.name, token: S.token }));
  };
  ws.onmessage = (e) => handle(JSON.parse(e.data));
  ws.onclose = () => { setConn(false); setTimeout(connect, 1500); };
}
const wsSend = (o) => S.ws?.readyState === 1 && S.ws.send(JSON.stringify(o));
function setConn(ok) { $('#meAvatar').style.outline = ok ? '' : '2px solid var(--danger)'; }

function lookup(name) {
  return new Promise((res) => {
    const rid = uid();
    S.pendingLookups[rid] = res;
    wsSend({ t: 'lookup', name, rid });
    setTimeout(() => { if (S.pendingLookups[rid]) { delete S.pendingLookups[rid]; res(null); } }, 5000);
  });
}
async function ensureContact(name) {
  if (S.contacts[name]?.ik) return S.contacts[name];
  const u = await lookup(name);
  if (!u) return null;
  S.contacts[name] = { ik: u.pub.ik, about: u.about, online: u.online, lastSeen: u.lastSeen };
  await persist();
  return S.contacts[name];
}

async function handle(m) {
  switch (m.t) {
    case 'registered':
      S.token = m.token;
      await idb.set('account', { name: S.name, token: S.token });
      await sessionStore.saveIdentity();
      showApp(); break;
    case 'authed':
      setConn(true);
      m.groups.forEach(upsertGroup);
      if ((m.opkCount ?? 20) < 10) topUpPrekeys();
      if (!$('#app').classList.contains('hidden')) break;
      showApp(); break;
    case 'prekeys_low': topUpPrekeys(); break;
    case 'autherror':
      $('#authError').textContent = 'Anmeldung fehlgeschlagen. Bitte neues Konto erstellen.';
      await idb.set('account', null); await idb.set('identity', null); showAuth(); break;
    case 'error': $('#authError').textContent = m.msg; toast(m.msg); break;
    case 'user': case 'nouser': {
      const r = S.pendingLookups[m.rid]; delete S.pendingLookups[m.rid];
      if (m.t === 'user' && S.contacts[m.name]?.ik && S.contacts[m.name].ik !== m.pub.ik) {
        S.contacts[m.name].keyChanged = true; // Identitätsschlüssel hat sich geändert – Nutzer warnen
      }
      r?.(m.t === 'user' ? m : null); break;
    }
    case 'bundle': case 'nobundle': {
      const r = S.pendingLookups[m.rid]; delete S.pendingLookups[m.rid];
      r?.(m.t === 'bundle' ? m.bundle : null); break;
    }
    case 'presence': {
      const c = S.contacts[m.name]; if (!c) break;
      c.online = m.online; if (m.lastSeen) c.lastSeen = m.lastSeen;
      renderList(); if (S.current === 'u:' + m.name) renderHeader(); break;
    }
    case 'typing': {
      const chat = S.chats[m.chat?.startsWith('g:') ? m.chat : 'u:' + m.from]; if (!chat) break;
      chat.typing = m.from; clearTimeout(chat.typingT);
      chat.typingT = setTimeout(() => { chat.typing = false; renderList(); if (S.current === chat.id) renderHeader(); }, 3000);
      renderList(); if (S.current === chat.id) renderHeader(); break;
    }
    case 'group': upsertGroup(m.group); await persist(); renderList(); if (S.current === 'g:' + m.group.id) renderHeader(); break;
    case 'ack': {
      const msg = findOwn(m.id); if (!msg) break;
      msg.state = 'sent'; msg.ts = m.ts; await idb.putMsg(msg); refreshMsg(msg); break;
    }
    case 'receipt': {
      for (const id of m.ids) {
        const msg = findOwn(id); if (!msg) continue;
        const prev = msg.rcpt[m.from];
        if (prev === 'read') continue;
        msg.rcpt[m.from] = m.state;
        await idb.putMsg(msg); refreshMsg(msg);
      }
      break;
    }
    case 'msg': await onIncoming(m); break;
  }
}

function upsertGroup(g) {
  S.groups[g.id] = g;
  const id = 'g:' + g.id;
  if (!g.members.includes(S.name)) { if (S.chats[id]) S.chats[id].left = true; return; }
  S.chats[id] ||= { id, type: 'g', target: g.id, last: { ts: g.created, preview: 'Gruppe erstellt' }, unread: 0 };
  g.members.forEach((n) => n !== S.name && ensureContact(n));
}

async function onIncoming(m) {
  const c = await ensureContact(m.from);
  if (!c) return;
  let p, res;
  try { res = await ratchet.decrypt(m.from, m.env); p = res.obj; }
  catch (e) { return console.warn('Entschlüsselung fehlgeschlagen', m.id, e.message); }
  // Beim ersten Kontakt den Identitätsschlüssel des Absenders festhalten; ändert er sich später, warnen.
  if (res.peerIk) {
    if (!c.ikVerified) { c.ikVerified = res.peerIk; await persist(); }
    else if (c.ikVerified !== res.peerIk) { c.keyChanged = true; await persist(); }
  }
  wsSend({ t: 'receipt', to: m.from, ids: [m.id], state: 'delivered' });

  if (p.kind === 'status') {
    if (!S.statuses.find((s) => s.id === m.id)) S.statuses.push({ id: m.id, from: m.from, ts: m.ts, ...p });
    await persist(); renderStatusList(); return;
  }
  if (p.kind === 'delete') {
    const msg = await idb.getMsg(p.target);
    if (msg && msg.from === m.from) { msg.deleted = true; msg.text = ''; msg.data = null; await idb.putMsg(msg); refreshMsg(msg); updateLast(msg.chat); }
    return;
  }
  const chatId = p.g ? 'g:' + p.g : 'u:' + m.from;
  if (p.g && !S.groups[p.g]) return;
  const msg = { id: m.id, chat: chatId, from: m.from, ts: m.ts, kind: p.kind, text: p.text, data: p.data,
    fname: p.fname, mime: p.mime, dur: p.dur, reply: p.reply, state: 'in', readSent: false };
  if (await idb.getMsg(msg.id)) return;
  await idb.putMsg(msg);
  const chat = S.chats[chatId] ||= { id: chatId, type: p.g ? 'g' : 'u', target: p.g || m.from, unread: 0 };
  (S.msgs[chatId] ||= []).push(msg);
  chat.last = { ts: msg.ts, preview: preview(msg), from: m.from };
  chat.typing = false;
  if (S.current === chatId && document.visibilityState === 'visible') {
    appendMsg(msg); markRead(chatId);
  } else {
    chat.unread = (chat.unread || 0) + 1;
    notify(chatTitle(chat), (p.g ? m.from + ': ' : '') + preview(msg));
  }
  await persist(); renderList();
  if (S.current === chatId) renderHeader();
}

function notify(title, body) {
  if (document.visibilityState === 'visible' && document.hasFocus()) return;
  if ('Notification' in window && Notification.permission === 'granted') new Notification(title, { body, icon: '/icon.svg' });
}

function findOwn(id) {
  for (const list of Object.values(S.msgs)) { const m = list.find((x) => x.id === id && x.from === S.name); if (m) return m; }
  return null;
}
function recipientsOf(chatId) {
  const chat = S.chats[chatId];
  if (chat.type === 'u') return [chat.target];
  return (S.groups[chat.target]?.members || []).filter((n) => n !== S.name);
}

async function sendPayload(chatId, payload, msgId = uid()) {
  const chat = S.chats[chatId];
  if (chat.type === 'g') payload.g = chat.target;
  const envs = {};
  for (const n of recipientsOf(chatId)) {
    const c = await ensureContact(n);
    if (c) try { envs[n] = await ratchet.encrypt(n, payload); } catch (e) { console.warn('Verschlüsselung für', n, 'fehlgeschlagen', e.message); }
  }
  if (Object.keys(envs).length) wsSend({ t: 'send', id: msgId, envs });
  return msgId;
}

async function sendMessage(payload) {
  const chatId = S.current; if (!chatId) return;
  if (S.replyTo) { payload.reply = S.replyTo; setReply(null); }
  const id = uid();
  const rcpt = Object.fromEntries(recipientsOf(chatId).map((n) => [n, 'sent']));
  const msg = { id, chat: chatId, from: S.name, ts: Date.now(), ...payload, state: 'pending', rcpt };
  await idb.putMsg(msg);
  (S.msgs[chatId] ||= []).push(msg);
  S.chats[chatId].last = { ts: msg.ts, preview: preview(msg), from: S.name };
  appendMsg(msg); renderList(); persist();
  await sendPayload(chatId, { ...payload }, id);
}

function markRead(chatId) {
  const chat = S.chats[chatId]; if (!chat) return;
  chat.unread = 0;
  const bySender = {};
  for (const m of S.msgs[chatId] || []) {
    if (m.from !== S.name && !m.readSent) { m.readSent = true; (bySender[m.from] ||= []).push(m.id); idb.putMsg(m); }
  }
  Object.entries(bySender).forEach(([to, ids]) => wsSend({ t: 'receipt', to, ids, state: 'read' }));
  persist(); renderList();
}

function preview(m) {
  if (m.deleted) return '🚫 Nachricht gelöscht';
  return { text: m.text, image: '📷 Foto' + (m.text ? ': ' + m.text : ''), audio: '🎤 Sprachnachricht', file: '📎 ' + (m.fname || 'Datei') }[m.kind] || '';
}
function chatTitle(chat) { return chat.type === 'g' ? (S.groups[chat.target]?.name || 'Gruppe') : chat.target; }
function updateLast(chatId) {
  const list = S.msgs[chatId] || []; const m = list[list.length - 1];
  if (m) S.chats[chatId].last = { ts: m.ts, preview: preview(m), from: m.from };
  renderList(); persist();
}

// ---------------- Rendering: Liste ----------------
function renderList() {
  const q = $('#search').value.trim().toLowerCase();
  const chats = Object.values(S.chats).filter((c) => chatTitle(c).toLowerCase().includes(q))
    .sort((a, b) => (b.last?.ts || 0) - (a.last?.ts || 0));
  const html = chats.map((c) => {
    const title = chatTitle(c);
    const online = c.type === 'u' && S.contacts[c.target]?.online;
    let pv = c.typing ? `<span style="color:var(--accent)">${c.type === 'g' ? esc(c.typing) + ' ' : ''}schreibt…</span>` : '';
    if (!pv && c.last) {
      let tick = '';
      if (c.last.from === S.name) { const lm = (S.msgs[c.id] || []).at(-1); tick = lm ? tickHTML(lm) + ' ' : ''; }
      const who = c.type === 'g' && c.last.from && c.last.from !== S.name ? esc(c.last.from) + ': ' : '';
      pv = tick + who + esc(c.last.preview);
    }
    return `<div class="item ${S.current === c.id ? 'active' : ''}" data-chat="${esc(c.id)}">
      ${avatarHTML(title, { online, group: c.type === 'g' })}
      <div class="body"><div class="row"><span class="title">${esc(title)}</span>
        <span class="time ${c.unread ? 'unread' : ''}">${c.last ? fmtListTime(c.last.ts) : ''}</span></div>
        <div class="row"><span class="preview">${pv}</span>${c.unread ? `<span class="badge">${c.unread}</span>` : ''}</div></div></div>`;
  }).join('');
  $('#chatList').innerHTML = html || `<div class="empty-inner" style="padding:40px 20px;text-align:center" class="muted">
    <p class="muted">Noch keine Chats.</p><button class="btn primary" onclick="openNewChat()">Neuen Chat starten</button></div>`;
  const total = Object.values(S.chats).reduce((a, c) => a + (c.unread || 0), 0);
  document.title = (total ? `(${total}) ` : '') + 'Krypto-Messenger';
}

function renderStatusList() {
  const now = Date.now();
  S.statuses = S.statuses.filter((s) => now - s.ts < 864e5);
  const mine = S.statuses.filter((s) => s.from === S.name);
  const others = {};
  S.statuses.filter((s) => s.from !== S.name).forEach((s) => (others[s.from] ||= []).push(s));
  const row = (name, list, label) => {
    const unseen = list.some((s) => !S.seenStatus[s.id]);
    return `<div class="item" data-status="${esc(name)}">
      ${avatarHTML(name, { cls: 'ring' + (unseen || name === S.name ? '' : ' seen') })}
      <div class="body"><div class="title">${esc(label)}</div><div class="preview">${fmtListTime(list.at(-1).ts)}</div></div></div>`;
  };
  let html = `<div class="item" id="addStatus">${avatarHTML(S.name)}<div class="body"><div class="title">Mein Status</div>
    <div class="preview">${mine.length ? mine.length + ' Update(s) · tippen zum Hinzufügen' : 'Status hinzufügen'}</div></div>
    <button class="icon round" title="Neuer Status">＋</button></div>`;
  if (mine.length) html += row(S.name, mine, 'Meine Updates ansehen');
  const names = Object.keys(others);
  if (names.length) html += `<div class="section-label">Neueste Updates</div>` + names.map((n) => row(n, others[n], n)).join('');
  else html += `<p class="muted" style="padding:16px;text-align:center">Keine Status-Updates von Kontakten.</p>`;
  $('#statusList').innerHTML = html;
}

// ---------------- Rendering: Unterhaltung ----------------
function tickHTML(m) {
  if (m.from !== S.name) return '';
  if (m.state === 'pending') return '<span class="tick">🕓</span>';
  const states = Object.values(m.rcpt || {});
  if (states.length && states.every((s) => s === 'read')) return '<span class="tick read">✓✓</span>';
  if (states.length && states.every((s) => s === 'read' || s === 'delivered')) return '<span class="tick">✓✓</span>';
  return '<span class="tick">✓</span>';
}
function msgHTML(m, prev) {
  const out = m.from === S.name;
  const chat = S.chats[m.chat];
  const cont = prev && prev.from === m.from && m.ts - prev.ts < 60000 && fmtDay(prev.ts) === fmtDay(m.ts);
  const onlyEmoji = m.kind === 'text' && /^(\p{Extended_Pictographic}|️|‍|\s){1,12}$/u.test(m.text || '') && [...(m.text || '').trim()].length <= 6;
  let body = '';
  if (m.deleted) body = `<div class="text muted"><i>🚫 Diese Nachricht wurde gelöscht</i></div>`;
  else {
    if (m.reply) body += `<div class="quote"><b>${esc(m.reply.from === S.name ? 'Du' : m.reply.from)}</b><br>${esc(m.reply.preview)}</div>`;
    if (m.kind === 'image') body += `<img class="media" src="${esc(m.data)}" alt="Bild">`;
    if (m.kind === 'audio') body += `<audio controls preload="metadata" src="${esc(m.data)}"></audio>`;
    if (m.kind === 'file') body += `<a class="file" href="${esc(m.data)}" download="${esc(m.fname)}">📄 <span>${esc(m.fname)}</span></a>`;
    if (m.text) body += `<div class="text">${linkify(esc(m.text))}</div>`;
  }
  const author = chat?.type === 'g' && !out && !cont ? `<div class="author" style="color:${colorOf(m.from)}">${esc(m.from)}</div>` : '';
  return `<div class="msg ${out ? 'out' : 'in'} ${cont ? 'cont' : ''} ${onlyEmoji && !m.reply ? 'big-emoji' : ''}" data-id="${m.id}">
    ${m.deleted ? '' : '<button class="menu" title="Optionen">⌄</button>'}${author}${body}
    <span class="meta">${fmtTime(m.ts)} ${tickHTML(m)}</span></div>`;
}
const linkify = (s) => s.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');

function renderMessages() {
  const list = S.msgs[S.current] || [];
  let html = `<div class="e2e-note">🔒 Nachrichten sind Ende-zu-Ende-verschlüsselt. Niemand außerhalb dieses Chats kann sie lesen, auch nicht der Server.</div>`;
  let day = null, prev = null;
  for (const m of list) {
    const d = fmtDay(m.ts);
    if (d !== day) { html += `<div class="daysep">${d}</div>`; day = d; prev = null; }
    html += msgHTML(m, prev); prev = m;
  }
  const box = $('#messages'); box.innerHTML = html; box.scrollTop = box.scrollHeight;
}
function appendMsg(m) {
  if (S.current !== m.chat) return;
  const list = S.msgs[m.chat]; const prev = list[list.length - 2];
  const box = $('#messages');
  if (!prev || fmtDay(prev.ts) !== fmtDay(m.ts)) box.insertAdjacentHTML('beforeend', `<div class="daysep">${fmtDay(m.ts)}</div>`);
  box.insertAdjacentHTML('beforeend', msgHTML(m, prev && fmtDay(prev.ts) === fmtDay(m.ts) ? prev : null));
  box.scrollTop = box.scrollHeight;
}
function refreshMsg(m) {
  if (S.current === m.chat) {
    const el = document.querySelector(`.msg[data-id="${m.id}"]`);
    if (el) { const list = S.msgs[m.chat]; const i = list.indexOf(m); el.outerHTML = msgHTML(m, list[i - 1] && fmtDay(list[i - 1].ts) === fmtDay(m.ts) ? list[i - 1] : null); }
  }
  renderList();
}
function renderHeader() {
  const chat = S.chats[S.current]; if (!chat) return;
  const title = chatTitle(chat);
  $('#convAvatar').outerHTML = avatarHTML(title, { group: chat.type === 'g' }).replace('class="avatar', 'id="convAvatar" class="avatar');
  $('#convName').textContent = title;
  const sub = $('#convSub');
  if (chat.typing) { sub.textContent = (chat.type === 'g' ? chat.typing + ' ' : '') + 'schreibt…'; sub.classList.add('typing'); }
  else {
    sub.classList.remove('typing');
    sub.textContent = chat.type === 'g' ? (S.groups[chat.target]?.members || []).map((n) => n === S.name ? 'Du' : n).join(', ')
      : (S.contacts[chat.target]?.keyChanged ? '⚠️ Sicherheitsnummer hat sich geändert' : lastSeenText(S.contacts[chat.target]));
  }
}

async function openChat(chatId) {
  S.current = chatId; setReply(null);
  if (!S.msgs[chatId]) S.msgs[chatId] = [];
  $('#empty').classList.add('hidden'); $('#conv').classList.remove('hidden');
  $('#app').classList.add('in-chat');
  renderHeader(); renderMessages(); markRead(chatId);
  const chat = S.chats[chatId];
  const left = chat.type === 'g' && !S.groups[chat.target]?.members.includes(S.name);
  $('.composer').classList.toggle('hidden', !!left);
  if (matchMedia('(min-width:761px)').matches) $('#input').focus();
}
function closeChat() { S.current = null; $('#app').classList.remove('in-chat'); $('#conv').classList.add('hidden'); $('#empty').classList.remove('hidden'); renderList(); }

// ---------------- Eingabe ----------------
function updateSendBtn() {
  const has = $('#input').value.trim().length > 0 || rec.active;
  $('#btnSend').innerHTML = has
    ? '<svg viewBox="0 0 24 24"><path d="M2 21 23 12 2 3v7l15 2-15 2z"/></svg>'
    : '<svg viewBox="0 0 24 24"><path d="M12 15a3 3 0 0 0 3-3V5a3 3 0 0 0-6 0v7a3 3 0 0 0 3 3zm5-3a5 5 0 0 1-10 0H5a7 7 0 0 0 6 6.9V22h2v-3.1a7 7 0 0 0 6-6.9h-2z"/></svg>';
  $('#btnSend').title = has ? 'Senden' : 'Sprachnachricht aufnehmen';
}
let typingSentAt = 0;
function onTyping() {
  updateSendBtn();
  const el = $('#input'); el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 120) + 'px';
  if (Date.now() - typingSentAt > 2000 && S.current) {
    typingSentAt = Date.now();
    wsSend({ t: 'typing', to: recipientsOf(S.current), chat: S.chats[S.current].type === 'g' ? S.current : null });
  }
}
async function onSend() {
  if (rec.active) return rec.stop(true);
  const text = $('#input').value.trim();
  if (!text) return rec.start();
  $('#input').value = ''; onTyping();
  await sendMessage({ kind: 'text', text });
}

// Sprachnachrichten
const rec = {
  active: false, chunks: [], mr: null, start0: 0, timer: null,
  async start() {
    if (!navigator.mediaDevices?.getUserMedia) return toast('Mikrofon wird hier nicht unterstützt');
    let stream;
    try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch { return toast('Kein Zugriff auf das Mikrofon'); }
    this.chunks = []; this.mr = new MediaRecorder(stream);
    this.mr.ondataavailable = (e) => e.data.size && this.chunks.push(e.data);
    this.mr.start(); this.active = true; this.start0 = Date.now();
    $('#input').classList.add('hidden'); $('#recBar').classList.remove('hidden');
    this.timer = setInterval(() => { const s = Math.floor((Date.now() - this.start0) / 1000); $('#recTime').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; }, 250);
    updateSendBtn();
  },
  stop(send) {
    if (!this.active) return;
    const dur = Math.round((Date.now() - this.start0) / 1000);
    this.mr.onstop = async () => {
      this.mr.stream.getTracks().forEach((t) => t.stop());
      if (send && this.chunks.length) {
        const blob = new Blob(this.chunks, { type: this.mr.mimeType || 'audio/webm' });
        await sendMessage({ kind: 'audio', data: await blobToDataURL(blob), dur });
      }
    };
    this.mr.stop(); this.active = false; clearInterval(this.timer);
    $('#input').classList.remove('hidden'); $('#recBar').classList.add('hidden'); $('#recTime').textContent = '0:00';
    updateSendBtn();
  },
};
const blobToDataURL = (b) => new Promise((r) => { const f = new FileReader(); f.onload = () => r(f.result); f.readAsDataURL(b); });

async function compressImage(file, max = 1600) {
  const url = URL.createObjectURL(file);
  const img = await new Promise((r, j) => { const i = new Image(); i.onload = () => r(i); i.onerror = j; i.src = url; });
  const scale = Math.min(1, max / Math.max(img.width, img.height));
  const c = document.createElement('canvas'); c.width = img.width * scale; c.height = img.height * scale;
  c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
  URL.revokeObjectURL(url);
  return c.toDataURL('image/jpeg', 0.85);
}
async function onFile(file, caption) {
  if (!file) return;
  if (file.size > 25 * 1024 * 1024) return toast('Datei ist zu groß (max. 25 MB)');
  if (file.type.startsWith('image/') && file.type !== 'image/gif') await sendMessage({ kind: 'image', data: await compressImage(file), text: caption || '' });
  else await sendMessage({ kind: 'file', data: await blobToDataURL(file), fname: file.name, mime: file.type });
}

function setReply(m) {
  S.replyTo = m ? { id: m.id, from: m.from, preview: preview(m) } : null;
  $('#replyBar').classList.toggle('hidden', !m);
  if (m) { $('#replyText').innerHTML = `<b>${esc(m.from === S.name ? 'Du' : m.from)}</b>: ${esc(preview(m))}`; $('#input').focus(); }
}

function openMsgMenu(id, x, y) {
  const m = (S.msgs[S.current] || []).find((x) => x.id === id); if (!m) return;
  closeMenu();
  const el = document.createElement('div'); el.className = 'ctx'; el.id = 'ctx';
  el.innerHTML = `<button data-a="reply">↩︎ Antworten</button>${m.text ? '<button data-a="copy">⧉ Kopieren</button>' : ''}
    <button data-a="delme">🗑 Für mich löschen</button>${m.from === S.name ? '<button data-a="delall">🗑 Für alle löschen</button>' : ''}`;
  document.body.appendChild(el);
  el.style.left = Math.min(x, innerWidth - 180) + 'px'; el.style.top = Math.min(y, innerHeight - el.offsetHeight - 10) + 'px';
  el.onclick = async (e) => {
    const a = e.target.dataset.a; closeMenu();
    if (a === 'reply') setReply(m);
    if (a === 'copy') { navigator.clipboard?.writeText(m.text); toast('Kopiert'); }
    if (a === 'delme') { S.msgs[S.current] = S.msgs[S.current].filter((x) => x.id !== id); await idb.delMsg(id); renderMessages(); updateLast(S.current); }
    if (a === 'delall') { m.deleted = true; m.text = ''; m.data = null; await idb.putMsg(m); refreshMsg(m); updateLast(S.current); sendPayload(S.current, { kind: 'delete', target: id }); }
  };
}
function closeMenu() { $('#ctx')?.remove(); }

// ---------------- Dialoge ----------------
function modal(html, onMount) {
  $('#modalCard').innerHTML = html; $('#modal').classList.remove('hidden');
  onMount?.($('#modalCard'));
}
function closeModal() { $('#modal').classList.add('hidden'); }

window.openNewChat = function () {
  modal(`<h3>Neuer Chat</h3><p class="muted small">Gib den Benutzernamen deines Kontakts ein.</p>
    <input id="ncName" placeholder="Benutzername" autocomplete="off"><p class="error" id="ncErr"></p>
    <div class="actions"><button class="btn" data-close>Abbrechen</button><button class="btn primary" id="ncGo">Chat starten</button></div>`, (c) => {
    const go = async () => {
      const name = c.querySelector('#ncName').value.trim();
      if (!name) return;
      if (name === S.name) return (c.querySelector('#ncErr').textContent = 'Das bist du selbst 🙂');
      const ct = await ensureContact(name);
      if (!ct) return (c.querySelector('#ncErr').textContent = 'Diesen Benutzer gibt es nicht.');
      const id = 'u:' + name;
      S.chats[id] ||= { id, type: 'u', target: name, unread: 0, last: null };
      await persist(); closeModal(); renderList(); openChat(id);
    };
    c.querySelector('#ncGo').onclick = go;
    c.querySelector('#ncName').onkeydown = (e) => e.key === 'Enter' && go();
    c.querySelector('#ncName').focus();
  });
};

function openNewGroup() {
  const names = Object.keys(S.contacts).filter((n) => n !== S.name);
  modal(`<h3>Neue Gruppe</h3><input id="ngName" placeholder="Gruppenname" maxlength="40">
    <div class="muted small">Mitglieder auswählen</div>
    <div>${names.map((n) => `<label class="check"><input type="checkbox" value="${esc(n)}">${avatarHTML(n)} ${esc(n)}</label>`).join('') || '<p class="muted small">Starte zuerst einen Chat mit Kontakten. Oder füge unten Namen hinzu.</p>'}</div>
    <input id="ngExtra" placeholder="Weitere Benutzernamen, mit Komma getrennt">
    <p class="error" id="ngErr"></p>
    <div class="actions"><button class="btn" data-close>Abbrechen</button><button class="btn primary" id="ngGo">Erstellen</button></div>`, (c) => {
    c.querySelector('#ngGo').onclick = async () => {
      const gname = c.querySelector('#ngName').value.trim();
      const members = [...c.querySelectorAll('input[type=checkbox]:checked')].map((i) => i.value);
      for (const n of c.querySelector('#ngExtra').value.split(',').map((s) => s.trim()).filter(Boolean)) {
        if (await ensureContact(n)) members.push(n); else return (c.querySelector('#ngErr').textContent = `„${n}“ gibt es nicht.`);
      }
      if (!gname) return (c.querySelector('#ngErr').textContent = 'Bitte einen Gruppennamen eingeben.');
      if (!members.length) return (c.querySelector('#ngErr').textContent = 'Bitte mindestens ein Mitglied wählen.');
      wsSend({ t: 'group_create', name: gname, members });
      closeModal(); toast('Gruppe wird erstellt…');
    };
  });
}

async function openSafety() {
  const chat = S.chats[S.current];
  if (chat.type === 'g') {
    const g = S.groups[chat.target];
    return modal(`<h3>${esc(g.name)}</h3><p class="muted small">Gruppe · ${g.members.length} Mitglieder · erstellt von ${esc(g.admin)}</p>
      ${g.members.map((n) => `<div class="check">${avatarHTML(n)} ${esc(n === S.name ? 'Du' : n)}</div>`).join('')}
      <p class="muted small">🔒 Jede Nachricht wird einzeln für jedes Mitglied verschlüsselt.</p>
      <div class="actions"><button class="btn danger" id="leave">Gruppe verlassen</button><button class="btn primary" data-close>Schließen</button></div>`, (c) => {
      c.querySelector('#leave').onclick = () => { wsSend({ t: 'group_leave', id: g.id }); closeModal(); closeChat(); };
    });
  }
  const ct = S.contacts[chat.target];
  const nums = await safetyNumber(S.identity.ikPub, ct.ikVerified || ct.ik);
  modal(`<h3>Verschlüsselung prüfen</h3>
    <p class="muted small">Vergleiche diese Nummer mit ${esc(chat.target)}, am besten persönlich oder per Anruf. Stimmt sie überein, ist euer Chat Ende-zu-Ende-verschlüsselt und niemand sitzt dazwischen.</p>
    <div class="safety">${nums.map((n) => `<span>${n}</span>`).join('')}</div>
    ${ct.keyChanged ? '<p class="error">⚠️ Der Schlüssel dieses Kontakts hat sich geändert (neues Gerät?). Bitte erneut vergleichen.</p>' : ''}
    <div class="actions">${ct.keyChanged ? '<button class="btn" id="ack">Als geprüft markieren</button>' : ''}<button class="btn primary" data-close>Schließen</button></div>`, (c) => {
    c.querySelector('#ack')?.addEventListener('click', async () => { ct.keyChanged = false; await persist(); closeModal(); renderHeader(); });
  });
}

function openProfile() {
  modal(`${avatarHTML(S.name, { cls: 'lg' })}<h3 style="text-align:center">${esc(S.name)}</h3>
    <label class="muted small">Info</label><input id="pfAbout" maxlength="140" value="${esc(S.about || '')}" placeholder="Hey, ich nutze Krypto-Messenger!">
    <label class="check"><input type="checkbox" id="pfNotif" ${('Notification' in window && Notification.permission === 'granted') ? 'checked' : ''}> Benachrichtigungen</label>
    <p class="muted small">🔑 Dein privater Schlüssel liegt nur in diesem Browser. Wenn du die Browserdaten löschst, ist das Konto auf diesem Gerät weg.</p>
    <div class="actions"><button class="btn" data-close>Schließen</button><button class="btn primary" id="pfSave">Speichern</button></div>`, (c) => {
    c.querySelector('#pfNotif').onchange = (e) => { if (e.target.checked && 'Notification' in window) Notification.requestPermission(); };
    c.querySelector('#pfSave').onclick = async () => {
      S.about = c.querySelector('#pfAbout').value; await idb.set('about', S.about);
      wsSend({ t: 'about', about: S.about }); closeModal(); toast('Gespeichert');
    };
  });
}

function openStatusCompose() {
  const bgs = ['#0b8f6a', '#5b5fc7', '#e17076', '#f59f00', '#1c7ed6', '#212529'];
  let bg = bgs[0];
  modal(`<h3>Neuer Status</h3><p class="muted small">Sichtbar für deine Kontakte für 24 Stunden, Ende-zu-Ende-verschlüsselt.</p>
    <textarea class="field" id="stText" rows="3" maxlength="300" placeholder="Was gibt's Neues?"></textarea>
    <div class="colors">${bgs.map((c, i) => `<button style="background:${c}" data-bg="${c}" class="${i ? '' : 'sel'}"></button>`).join('')}</div>
    <label class="btn" style="text-align:center">📷 Foto wählen<input type="file" accept="image/*" id="stImg" hidden></label>
    <p class="muted small" id="stImgName"></p>
    <div class="actions"><button class="btn" data-close>Abbrechen</button><button class="btn primary" id="stGo">Teilen</button></div>`, (c) => {
    c.querySelectorAll('[data-bg]').forEach((b) => b.onclick = () => { bg = b.dataset.bg; c.querySelectorAll('[data-bg]').forEach((x) => x.classList.toggle('sel', x === b)); });
    c.querySelector('#stImg').onchange = (e) => c.querySelector('#stImgName').textContent = e.target.files[0]?.name || '';
    c.querySelector('#stGo').onclick = async () => {
      const text = c.querySelector('#stText').value.trim(); const f = c.querySelector('#stImg').files[0];
      if (!text && !f) return;
      const payload = { kind: 'status', text, bg, data: f ? await compressImage(f, 1200) : null };
      const id = uid();
      S.statuses.push({ id, from: S.name, ts: Date.now(), ...payload });
      const targets = Object.keys(S.contacts).filter((n) => n !== S.name);
      const envs = {};
      for (const n of targets) try { envs[n] = await ratchet.encrypt(n, payload); } catch {}
      if (Object.keys(envs).length) wsSend({ t: 'send', id, envs });
      await persist(); closeModal(); renderStatusList(); toast('Status geteilt');
    };
  });
}

function viewStatus(name) {
  const list = S.statuses.filter((s) => s.from === name).sort((a, b) => a.ts - b.ts);
  if (!list.length) return;
  let i = 0, timer;
  const v = $('#viewer'); v.classList.remove('hidden');
  const close = () => { clearTimeout(timer); v.classList.add('hidden'); v.innerHTML = ''; persist(); renderStatusList(); };
  const show = () => {
    if (i >= list.length) return close();
    const s = list[i]; S.seenStatus[s.id] = true;
    v.style.background = s.data ? '#000' : s.bg;
    v.innerHTML = `<div class="bars">${list.map((_, j) => `<span><i style="width:${j < i ? 100 : 0}%"></i></span>`).join('')}</div>
      <div class="vhead">${avatarHTML(name)}<div><b>${esc(name === S.name ? 'Du' : name)}</b><div class="small">${fmtListTime(s.ts)}</div></div>
      <button class="icon" id="vClose">✕</button></div>
      <div class="vbody">${s.data ? `<div><img src="${esc(s.data)}">${s.text ? `<p>${esc(s.text)}</p>` : ''}</div>` : esc(s.text)}</div>`;
    const bar = v.querySelectorAll('.bars i')[i];
    requestAnimationFrame(() => { bar.style.transition = 'width 5s linear'; bar.style.width = '100%'; });
    v.querySelector('#vClose').onclick = (e) => { e.stopPropagation(); close(); };
    timer = setTimeout(() => { i++; show(); }, 5000);
  };
  v.onclick = (e) => { clearTimeout(timer); if (e.clientX < innerWidth / 3) i = Math.max(0, i - 1); else i++; show(); };
  show();
}

// ---------------- Start ----------------
const EMOJIS = '😀 😃 😄 😁 😆 😅 😂 🤣 😊 😇 🙂 😉 😍 🥰 😘 😋 😜 🤪 😎 🤩 🥳 😏 😢 😭 😤 😡 🤯 😱 🤔 🤗 🤫 😴 🙄 😬 🥺 👍 👎 👏 🙌 🙏 💪 👋 🤝 ✌️ 🤞 👌 ❤️ 🧡 💛 💚 💙 💜 🖤 💔 💯 🔥 ✨ 🎉 🎂 🎁 ☀️ 🌙 ⭐ 🌈 ☕ 🍕 🍻 ⚽ 🚗 ✈️ 🏠 📷 🎵 💡 ✅ ❌ ⚠️ 🔒'.split(' ');

function showAuth() { $('#auth').classList.remove('hidden'); $('#app').classList.add('hidden'); $('#authName').focus(); }
async function showApp() {
  $('#auth').classList.add('hidden'); $('#app').classList.remove('hidden');
  $('#meAvatar').style.background = colorOf(S.name); $('#meAvatar').textContent = initials(S.name);
  $('#meAvatar').title = S.name;
  renderList(); renderStatusList(); updateSendBtn();
}

async function boot() {
  const theme = localStorage.getItem('theme'); if (theme) document.documentElement.dataset.theme = theme;
  const account = await idb.get('account');
  S.identity = await idb.get('identity');
  ratchet = Signal.createManager(() => S.identity, sessionStore);
  S.contacts = (await idb.get('contacts')) || {};
  S.groups = (await idb.get('groups')) || {};
  S.chats = (await idb.get('chats')) || {};
  S.statuses = (await idb.get('statuses')) || [];
  S.seenStatus = (await idb.get('seenStatus')) || {};
  S.about = (await idb.get('about')) || '';
  Object.values(S.contacts).forEach((c) => (c.online = false));
  for (const m of await idb.allMsgs()) (S.msgs[m.chat] ||= []).push(m);
  Object.values(S.msgs).forEach((l) => l.sort((a, b) => a.ts - b.ts));
  if (account?.token && S.identity) { Object.assign(S, { name: account.name, token: account.token }); showApp(); }
  else showAuth();
  connect();

  $('#authForm').onsubmit = async (e) => {
    e.preventDefault();
    $('#authError').textContent = '';
    const name = $('#authName').value.trim();
    const { id, keys } = await newIdentity();
    Object.assign(S, { name, identity: id, token: null });
    wsSend({ t: 'register', name, keys });
  };
  $('#search').oninput = renderList;
  $('#chatList').onclick = (e) => { const it = e.target.closest('[data-chat]'); if (it) openChat(it.dataset.chat); };
  $('#statusList').onclick = (e) => {
    if (e.target.closest('#addStatus')) return openStatusCompose();
    const it = e.target.closest('[data-status]'); if (it) viewStatus(it.dataset.status);
  };
  document.querySelectorAll('.tab').forEach((t) => t.onclick = () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === t));
    $('#chatList').classList.toggle('hidden', t.dataset.tab !== 'chats');
    $('#statusList').classList.toggle('hidden', t.dataset.tab !== 'status');
    $('.search').classList.toggle('hidden', t.dataset.tab !== 'chats');
    if (t.dataset.tab === 'status') renderStatusList();
  });
  $('#btnNewChat').onclick = openNewChat;
  $('#btnNewGroup').onclick = openNewGroup;
  $('#meAvatar').onclick = openProfile;
  $('#btnTheme').onclick = () => {
    const dark = getComputedStyle(document.documentElement).getPropertyValue('--panel').trim() === '#111b21';
    document.documentElement.dataset.theme = dark ? 'light' : 'dark'; localStorage.setItem('theme', dark ? 'light' : 'dark');
  };
  $('#btnBack').onclick = closeChat;
  $('#btnSafety').onclick = openSafety;
  $('#convInfoBtn').onclick = openSafety;
  $('#input').oninput = onTyping;
  $('#input').onkeydown = (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSend(); } };
  $('#btnSend').onclick = onSend;
  $('#recCancel').onclick = () => rec.stop(false);
  $('#fileInput').onchange = (e) => { onFile(e.target.files[0]); e.target.value = ''; };
  $('#replyCancel').onclick = () => setReply(null);
  $('#emojiPanel').innerHTML = EMOJIS.map((x) => `<button>${x}</button>`).join('');
  $('#btnEmoji').onclick = () => $('#emojiPanel').classList.toggle('hidden');
  $('#emojiPanel').onclick = (e) => { if (e.target.tagName === 'BUTTON') { $('#input').value += e.target.textContent; onTyping(); $('#input').focus(); } };
  $('#messages').onclick = (e) => {
    const mb = e.target.closest('.menu');
    if (mb) { e.stopPropagation(); const r = mb.getBoundingClientRect(); return openMsgMenu(mb.closest('.msg').dataset.id, r.left, r.bottom); }
    if (e.target.matches('img.media')) { const v = $('#viewer'); v.style.background = '#000'; v.innerHTML = `<div class="vhead"><button class="icon" id="vClose">✕</button></div><div class="vbody"><img src="${e.target.src}"></div>`; v.classList.remove('hidden'); v.onclick = () => v.classList.add('hidden'); }
  };
  $('#messages').oncontextmenu = (e) => { const m = e.target.closest('.msg'); if (m) { e.preventDefault(); openMsgMenu(m.dataset.id, e.clientX, e.clientY); } };
  $('#conv').addEventListener('dragover', (e) => e.preventDefault());
  $('#conv').addEventListener('drop', (e) => { e.preventDefault(); onFile(e.dataTransfer.files[0]); });
  $('#input').addEventListener('paste', (e) => { const f = [...e.clipboardData.files][0]; if (f) { e.preventDefault(); onFile(f); } });
  document.addEventListener('click', (e) => { if (!e.target.closest('.ctx')) closeMenu(); if (e.target.matches('[data-close]') || e.target.id === 'modal') closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeModal(); closeMenu(); $('#emojiPanel').classList.add('hidden'); } });
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && S.current) markRead(S.current); });
  if (false && 'serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('/sw.js').catch(() => {});
}
boot();

// ---- Demo-Hilfen ----
const DEMO_USER = new URLSearchParams(location.search).get('u');
window.demoReady = new Promise((res) => {
  const t = setInterval(() => { if (S.ws?.readyState === 1) { clearInterval(t);
    if (!S.token) { $('#authName').value = DEMO_USER; $('#authForm').requestSubmit(); }
    const w = setInterval(() => { if (S.token && !$('#app').classList.contains('hidden')) { clearInterval(w); res(); } }, 50);
  } }, 50);
});
window.demoOpenChat = async (name) => { await ensureContact(name); const id = 'u:' + name;
  S.chats[id] ||= { id, type: 'u', target: name, unread: 0, last: null }; renderList(); await openChat(id); };
window.demoSend = (text) => sendMessage({ kind: 'text', text });
window.demoCreateGroup = async (name, members) => { for (const n of members) await ensureContact(n); wsSend({ t: 'group_create', name, members }); };
window.demoOpenGroup = async () => { const c = Object.values(S.chats).find((c) => c.type === 'g'); if (c) await openChat(c.id); };
