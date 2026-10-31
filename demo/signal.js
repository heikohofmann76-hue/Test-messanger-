'use strict';
/* Signal-artiges Protokoll mit WebCrypto: X3DH-Schlüsselaustausch + Double Ratchet.
 *
 * - Identitätsschlüssel IK (ECDH) und Signaturschlüssel (ECDSA), beide P-256
 * - Signierter Prekey (SPK) und Einmal-Prekeys (OPK), die der Server verteilt
 * - Double Ratchet: neuer DH-Schlüssel bei jedem Sprecherwechsel, neuer Nachrichtenschlüssel
 *   für jede Nachricht. Alte Schlüssel werden verworfen (Forward Secrecy), und nach einem
 *   DH-Schritt ist eine Sitzung auch nach einem Schlüsselleck wieder sicher (Post-Compromise Security).
 * - Nachrichten außer der Reihe werden über gespeicherte übersprungene Schlüssel entschlüsselt.
 *
 * Unterschied zu Signal: P-256 statt Curve25519 (in allen Browsern verfügbar) und AES-GCM statt AES-CBC+HMAC.
 */
const Signal = (() => {
  const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
  const te = new TextEncoder(), td = new TextDecoder();
  const toB64 = (buf) => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s); };
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const concat = (...arrs) => { const out = new Uint8Array(arrs.reduce((a, x) => a + x.length, 0)); let o = 0; for (const x of arrs) { out.set(x, o); o += x.length; } return out; };
  const MAX_SKIP = 1000;

  const genDH = () => crypto.subtle.generateKey(CURVE, false, ['deriveBits']);
  const pubRaw = async (k) => toB64(await crypto.subtle.exportKey('raw', k));
  const dh = async (priv, pubB64) => {
    const pub = await crypto.subtle.importKey('raw', fromB64(pubB64), CURVE, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256));
  };
  const hkdf = async (ikm, salt, info, len) => {
    const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) }, k, len * 8));
  };
  const hmac = async (key, data) => {
    const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
  };
  const kdfRK = async (rk, dhOut) => { const o = await hkdf(dhOut, rk, 'KM-Ratchet', 64); return [o.slice(0, 32), o.slice(32)]; };
  const kdfCK = async (ck) => [await hmac(ck, new Uint8Array([2])), await hmac(ck, new Uint8Array([1]))]; // [nächster CK, Nachrichtenschlüssel]
  const aead = async (mk, mode, data, ad) => {
    // Jeder Nachrichtenschlüssel wird genau einmal benutzt, daher dürfen Schlüssel und IV daraus abgeleitet werden.
    const o = await hkdf(mk, new Uint8Array(32), 'KM-Message', 44);
    const key = await crypto.subtle.importKey('raw', o.slice(0, 32), 'AES-GCM', false, [mode]);
    return new Uint8Array(await crypto.subtle[mode]({ name: 'AES-GCM', iv: o.slice(32), additionalData: ad }, key, data));
  };

  // ---------- Identität und Prekeys ----------
  async function createIdentity() {
    const ik = await genDH();
    const sig = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const id = { ik, ikPub: await pubRaw(ik.publicKey), sig, sigPub: await pubRaw(sig.publicKey), spk: null, opks: {}, nextOpk: 1 };
    const spkKp = await genDH();
    const spkPub = await pubRaw(spkKp.publicKey);
    const spkSig = toB64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, sig.privateKey, fromB64(spkPub)));
    id.spk = { id: Date.now(), kp: spkKp, pub: spkPub, sig: spkSig };
    return id;
  }
  const publicIdentity = (id) => ({ ik: id.ikPub, sigPub: id.sigPub });
  const publicSpk = (id) => ({ id: id.spk.id, pub: id.spk.pub, sig: id.spk.sig });
  async function newOneTimePrekeys(id, n) {
    const out = [];
    for (let i = 0; i < n; i++) {
      const kp = await genDH();
      const k = { id: id.nextOpk++, pub: await pubRaw(kp.publicKey) };
      id.opks[k.id] = kp; out.push(k);
    }
    return out;
  }
  async function verifyBundle(b) {
    const key = await crypto.subtle.importKey('raw', fromB64(b.sigPub), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, fromB64(b.spk.sig), fromB64(b.spk.pub));
  }

  // ---------- X3DH ----------
  const F = new Uint8Array(32).fill(0xff);
  async function initOutgoing(id, b) {
    if (!(await verifyBundle(b))) throw new Error('Prekey-Signatur ungültig');
    const ek = await genDH();
    const parts = [F, await dh(id.ik.privateKey, b.spk.pub), await dh(ek.privateKey, b.ik), await dh(ek.privateKey, b.spk.pub)];
    if (b.opk) parts.push(await dh(ek.privateKey, b.opk.pub));
    const sk = await hkdf(concat(...parts), new Uint8Array(32), 'KM-X3DH', 32);
    const dhs = await genDH();
    const [rk, cks] = await kdfRK(sk, await dh(dhs.privateKey, b.spk.pub));
    return {
      peerIk: b.ik, rk, dhs, dhsPub: await pubRaw(dhs.publicKey), dhr: b.spk.pub, cks, ckr: null,
      ns: 0, nr: 0, pn: 0, skipped: {},
      pending: { ik: id.ikPub, ek: await pubRaw(ek.publicKey), spkId: b.spk.id, opkId: b.opk?.id || null },
      ad: toB64(concat(fromB64(id.ikPub), fromB64(b.ik))),
    };
  }
  async function initIncoming(id, pre) {
    if (pre.spkId !== id.spk.id) throw new Error('Unbekannter signierter Prekey');
    const parts = [F, await dh(id.spk.kp.privateKey, pre.ik), await dh(id.ik.privateKey, pre.ek), await dh(id.spk.kp.privateKey, pre.ek)];
    if (pre.opkId) {
      const opk = id.opks[pre.opkId];
      if (!opk) throw new Error('Einmal-Prekey schon verbraucht');
      parts.push(await dh(opk.privateKey, pre.ek));
    }
    const sk = await hkdf(concat(...parts), new Uint8Array(32), 'KM-X3DH', 32);
    return {
      peerIk: pre.ik, rk: sk, dhs: id.spk.kp, dhsPub: id.spk.pub, dhr: null, cks: null, ckr: null,
      ns: 0, nr: 0, pn: 0, skipped: {}, pending: null,
      ad: toB64(concat(fromB64(pre.ik), fromB64(id.ikPub))),
    };
  }

  // ---------- Double Ratchet ----------
  async function ratchetEncrypt(s, pt) {
    const [ck, mk] = await kdfCK(s.cks); s.cks = ck;
    const header = { dh: s.dhsPub, pn: s.pn, n: s.ns };
    if (s.pending) header.pre = s.pending;
    s.ns++;
    const hb = te.encode(JSON.stringify(header));
    const ct = await aead(mk, 'encrypt', pt, concat(fromB64(s.ad), hb));
    return { h: toB64(hb), c: toB64(ct) };
  }
  async function skipKeys(s, until) {
    if (!s.ckr) return;
    if (until - s.nr > MAX_SKIP) throw new Error('Zu viele übersprungene Nachrichten');
    while (s.nr < until) {
      const [ck, mk] = await kdfCK(s.ckr); s.ckr = ck;
      s.skipped[s.dhr + ':' + s.nr] = mk; s.nr++;
    }
    const keys = Object.keys(s.skipped);
    if (keys.length > 2000) keys.slice(0, keys.length - 2000).forEach((k) => delete s.skipped[k]);
  }
  async function dhRatchet(s, dhPub) {
    s.pn = s.ns; s.ns = 0; s.nr = 0; s.dhr = dhPub;
    [s.rk, s.ckr] = await kdfRK(s.rk, await dh(s.dhs.privateKey, dhPub));
    s.dhs = await genDH(); s.dhsPub = await pubRaw(s.dhs.publicKey);
    [s.rk, s.cks] = await kdfRK(s.rk, await dh(s.dhs.privateKey, s.dhr));
  }
  async function ratchetDecrypt(s, env) {
    const hb = fromB64(env.h);
    const header = JSON.parse(td.decode(hb));
    const ad = concat(fromB64(s.ad), hb);
    const sk = header.dh + ':' + header.n;
    if (s.skipped[sk]) {
      const pt = await aead(s.skipped[sk], 'decrypt', fromB64(env.c), ad);
      delete s.skipped[sk]; return pt;
    }
    if (header.dh !== s.dhr) { await skipKeys(s, header.pn); await dhRatchet(s, header.dh); }
    await skipKeys(s, header.n);
    const [ck, mk] = await kdfCK(s.ckr); s.ckr = ck; s.nr++;
    const pt = await aead(mk, 'decrypt', fromB64(env.c), ad);
    s.pending = null; // Gegenseite hat geantwortet, Prekey-Daten werden nicht mehr gebraucht
    return pt;
  }

  // ---------- Sitzungsverwaltung ----------
  // store: { loadSessions(peer), saveSessions(peer, list), saveIdentity(), fetchBundle(peer) }
  function createManager(getIdentity, store) {
    const locks = new Map();
    const withLock = (peer, fn) => {
      const prev = locks.get(peer) || Promise.resolve();
      const next = prev.then(fn, fn);
      locks.set(peer, next.catch(() => {}));
      return next;
    };
    return {
      encrypt: (peer, obj) => withLock(peer, async () => {
        const id = getIdentity();
        const list = (await store.loadSessions(peer)) || [];
        if (!list.length) {
          const b = await store.fetchBundle(peer);
          if (!b) throw new Error('Kein Prekey-Bundle für ' + peer);
          list.unshift(await initOutgoing(id, b));
        }
        const env = await ratchetEncrypt(list[0], te.encode(JSON.stringify(obj)));
        await store.saveSessions(peer, list);
        return env;
      }),
      decrypt: (peer, env) => withLock(peer, async () => {
        const id = getIdentity();
        const list = (await store.loadSessions(peer)) || [];
        for (let i = 0; i < list.length; i++) {
          const s = structuredClone(list[i]);
          try {
            const pt = await ratchetDecrypt(s, env);
            list.splice(i, 1); list.unshift(s);
            await store.saveSessions(peer, list);
            return { obj: JSON.parse(td.decode(pt)), peerIk: s.peerIk };
          } catch {}
        }
        const header = JSON.parse(td.decode(fromB64(env.h)));
        if (!header.pre) throw new Error('Keine passende Sitzung');
        const s = await initIncoming(id, header.pre);
        const pt = await ratchetDecrypt(s, env);
        if (header.pre.opkId) { delete id.opks[header.pre.opkId]; await store.saveIdentity(); }
        list.unshift(s);
        await store.saveSessions(peer, list.slice(0, 3));
        return { obj: JSON.parse(td.decode(pt)), peerIk: s.peerIk, newSession: true };
      }),
      reset: (peer) => withLock(peer, () => store.saveSessions(peer, [])),
    };
  }

  return { createIdentity, publicIdentity, publicSpk, newOneTimePrekeys, createManager, toB64, fromB64 };
})();
