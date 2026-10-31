'use strict';
/* WebRTC-Transport: direkte Verbindung zwischen zwei Geräten für den Nachrichtenversand.
 *
 * Idee: Der Server dient nur noch zum "Signaling" (die beiden Geräte tauschen über ihn
 * einmalig Verbindungsdaten aus) und als Fallback, wenn der Partner offline ist. Die
 * eigentlichen Nachrichten laufen danach direkt Gerät-zu-Gerät über einen DataChannel –
 * das spart Serverkosten und -traffic. Die Ende-zu-Ende-Verschlüsselung (signal.js) liegt
 * unverändert darüber, der DataChannel trägt also nur Chiffretext.
 *
 * Verbindungsaufbau nach dem "Perfect Negotiation"-Muster (ein Gerät ist höflich, das
 * andere nicht), damit gleichzeitige Verbindungsversuche sich nicht gegenseitig stören.
 *
 * STUN ist kostenlos (Google). TURN (nur nötig hinter strengen Firewalls) kann optional
 * über window.MESSENGER_ICE ergänzt werden.
 */
const P2P = (() => {
  const DEFAULT_ICE = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
  const peers = new Map(); // name -> { pc, dc, makingOffer, polite, queue:[] }
  let self = null, cfg = null;
  // cfg: { me, sendSignal(to, data), onEnvelope({from,id,ts,env}), onState(name, connected) }

  function iceServers() {
    const extra = (typeof window !== 'undefined' && window.MESSENGER_ICE) || [];
    return { iceServers: [...DEFAULT_ICE, ...extra] };
  }

  function init(c) { cfg = c; self = c.me; }

  function get(name) {
    let p = peers.get(name);
    if (p) return p;
    p = { pc: null, dc: null, makingOffer: false, polite: self < name, queue: [], ignoreOffer: false };
    peers.set(name, p);
    return p;
  }

  function wireChannel(p, name) {
    p.dc.binaryType = 'arraybuffer';
    p.dc.onopen = () => { cfg.onState?.(name, true); flush(p); };
    p.dc.onclose = () => cfg.onState?.(name, false);
    p.dc.onmessage = (e) => {
      let m; try { m = JSON.parse(e.data); } catch { return; }
      if (m.t === 'msg') cfg.onEnvelope({ from: name, id: m.id, ts: m.ts || Date.now(), env: m.env });
    };
  }

  function ensurePc(name) {
    const p = get(name);
    if (p.pc) return p;
    const pc = new RTCPeerConnection(iceServers());
    p.pc = pc;
    pc.onicecandidate = ({ candidate }) => candidate && cfg.sendSignal(name, { candidate });
    pc.onconnectionstatechange = () => {
      if (['failed', 'closed', 'disconnected'].includes(pc.connectionState)) teardown(name);
    };
    pc.onnegotiationneeded = async () => {
      try {
        p.makingOffer = true;
        await pc.setLocalDescription();
        cfg.sendSignal(name, { description: pc.localDescription });
      } catch (e) { console.warn('P2P negotiation', e); }
      finally { p.makingOffer = false; }
    };
    pc.ondatachannel = ({ channel }) => { p.dc = channel; wireChannel(p, name); };
    return p;
  }

  // Aktiv eine Verbindung zu name aufbauen (legt den DataChannel an → löst negotiationneeded aus).
  function connect(name) {
    if (name === self) return;
    const p = ensurePc(name);
    if (!p.dc) { p.dc = p.pc.createDataChannel('chat', { ordered: true }); wireChannel(p, name); }
  }

  async function handleSignal(name, data) {
    const p = ensurePc(name);
    const pc = p.pc;
    try {
      if (data.description) {
        const offerCollision = data.description.type === 'offer' && (p.makingOffer || pc.signalingState !== 'stable');
        p.ignoreOffer = !p.polite && offerCollision;
        if (p.ignoreOffer) return;
        await pc.setRemoteDescription(data.description);
        if (data.description.type === 'offer') {
          await pc.setLocalDescription();
          cfg.sendSignal(name, { description: pc.localDescription });
        }
      } else if (data.candidate) {
        try { await pc.addIceCandidate(data.candidate); } catch (e) { if (!p.ignoreOffer) throw e; }
      }
    } catch (e) { console.warn('P2P signal', e); }
  }

  function flush(p) { const q = p.queue; p.queue = []; q.forEach((m) => { try { p.dc.send(m); } catch {} }); }

  // Versucht, payload direkt zu senden. true = über DataChannel verschickt, false = bitte Fallback nutzen.
  function send(name, obj) {
    const p = peers.get(name);
    if (p?.dc && p.dc.readyState === 'open') {
      try { p.dc.send(JSON.stringify(obj)); return true; } catch { return false; }
    }
    return false;
  }

  function teardown(name) {
    const p = peers.get(name); if (!p) return;
    try { p.dc?.close(); } catch {}
    try { p.pc?.close(); } catch {}
    peers.delete(name);
    cfg.onState?.(name, false);
  }

  const isConnected = (name) => { const p = peers.get(name); return !!(p?.dc && p.dc.readyState === 'open'); };

  return { init, connect, handleSignal, send, teardown, isConnected, supported: typeof RTCPeerConnection !== 'undefined' };
})();
if (typeof window !== 'undefined') window.P2P = P2P;
