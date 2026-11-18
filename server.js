'use strict';
/* COMBATXIS: servidor para 2 jogadores. Sem dependencias: só Node. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
let ADMIN_KEY = process.env.ADMIN_KEY || '';
if (!ADMIN_KEY) {
  ADMIN_KEY = crypto.randomBytes(6).toString('hex');
  console.log('AVISO: ADMIN_KEY nao definida. Usando temporaria:', ADMIN_KEY);
}
const NAMES = [process.env.NOME1 || 'Jogador 1', process.env.NOME2 || 'Jogador 2'];
const tokenFor = slot => crypto.createHmac('sha256', ADMIN_KEY).update('combatxis-slot-' + slot).digest('hex').slice(0, 24);
const TOKENS = [tokenFor(0), tokenFor(1)];
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

const INDEX = path.join(__dirname, 'index.html');
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/' || u.pathname === '/index.html') {
    fs.readFile(INDEX, (err, data) => {
      if (err) { res.writeHead(500); return res.end('index.html nao encontrado'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(data);
    });
  } else if (u.pathname === '/convites') {
    if (!safeEq(u.searchParams.get('k') || '', ADMIN_KEY)) { res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Chave errada.'); }
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const proto = req.headers['x-forwarded-proto'] || 'http';
    const links = TOKENS.map(t => `${proto}://${host}/?i=${t}`);
    const card = (i, who) => `<div class="c"><h2>${esc(who)}</h2><input readonly id="l${i}" value="${esc(links[i])}" onclick="this.select()"><button onclick="cp(${i})">Copiar link</button> <button onclick="sh(${i})">Compartilhar</button></div>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(`<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Convites COMBATXIS</title>
<style>body{font-family:system-ui;background:#2a1624;color:#fff;padding:16px}.c{background:#0004;border-radius:12px;padding:14px;margin:12px 0}input{width:100%;box-sizing:border-box;padding:10px;font-size:13px}button{padding:10px 14px;margin-top:8px;font-size:15px}</style>
<h1>Convites COMBATXIS</h1><p>Cada link é de uma pessoa só. Não use o mesmo link nos dois celulares.</p>
${card(0, NAMES[0] + ' (você)')}${card(1, NAMES[1] + ' (sua namorada)')}
<script>const L=${JSON.stringify(links)};function cp(i){const e=document.getElementById('l'+i);e.select();(navigator.clipboard?navigator.clipboard.writeText(L[i]):Promise.reject()).then(()=>alert('Copiado!'),()=>{document.execCommand('copy');alert('Copiado!')})}function sh(i){if(navigator.share)navigator.share({title:'COMBATXIS',text:'Entra no COMBATXIS:',url:L[i]});else cp(i)}</script>`);
  } else if (u.pathname === '/saude') {
    res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('ok');
  } else { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('nao encontrado'); }
});

/* ---------- WebSocket minimo (RFC 6455) ---------- */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_PAYLOAD = 64 * 1024;

class Conn {
  constructor(socket) { this.s = socket; this.buf = Buffer.alloc(0); this.frag = null; this.alive = true; this.onmsg = null; this.onclose = null; this.closed = false;
    socket.on('data', d => this.data(d));
    socket.on('close', () => this.end());
    socket.on('error', () => this.end());
    socket.setNoDelay(true); }
  end() { if (this.closed) return; this.closed = true; try { this.s.destroy(); } catch (_) {} if (this.onclose) this.onclose(); }
  data(d) {
    this.buf = Buffer.concat([this.buf, d]);
    for (;;) {
      const b = this.buf; if (b.length < 2) return;
      const fin = (b[0] & 0x80) !== 0, op = b[0] & 0x0f, masked = (b[1] & 0x80) !== 0; let len = b[1] & 0x7f, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; const hi = b.readUInt32BE(2), lo = b.readUInt32BE(6); if (hi) return this.end(); len = lo; off = 10; }
      if (!masked || len > MAX_PAYLOAD) return this.end();
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4), p = Buffer.from(b.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < p.length; i++) p[i] ^= mask[i & 3];
      this.buf = b.subarray(off + 4 + len);
      if (op === 0x8) { this.send(0x8, Buffer.alloc(0)); return this.end(); }
      if (op === 0x9) { this.send(0xA, p); continue; }
      if (op === 0xA) { this.alive = true; continue; }
      if (op === 0x1 || op === 0x0) {
        if (op === 0x1) this.frag = [];
        if (!this.frag) return this.end();
        this.frag.push(p);
        if (fin) { const t = Buffer.concat(this.frag).toString('utf8'); this.frag = null; if (this.onmsg) this.onmsg(t); }
      }
    }
  }
  send(op, payload) {
    if (this.closed) return;
    const n = payload.length; let h;
    if (n < 126) h = Buffer.from([0x80 | op, n]);
    else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(n, 2); }
    else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeUInt32BE(n, 6); }
    try { this.s.write(Buffer.concat([h, payload])); } catch (_) { this.end(); }
  }
  text(str) { this.send(0x1, Buffer.from(str)); }
}

server.on('upgrade', (req, socket) => {
  const u = new URL(req.url, 'http://x');
  const key = req.headers['sec-websocket-key'];
  if (u.pathname !== '/ws' || !key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return; }
  const acc = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + '\r\n\r\n');
  newClient(new Conn(socket));
});

/* ---------- Estado do jogo ---------- */
const players = [null, null];          // conexoes por slot
const last = [null, null];             // ultimo estado 's' por slot
const kites = new Map();               // id -> {id, pal, owner, landed, P, Q}
const num = v => typeof v === 'number' && isFinite(v);
const nums = (a, n) => Array.isArray(a) && a.length === n && a.every(num);
const validPal = a => Array.isArray(a) && a.length === 4 && a.every(x => Number.isInteger(x) && x >= 0 && x <= 0xffffff);
const peerInfo = slot => players[1 - slot] ? { slot: 1 - slot, name: NAMES[1 - slot] } : null;
const toSlot = (slot, o) => { const c = players[slot]; if (c) c.text(JSON.stringify(o)); };
const toBoth = o => { toSlot(0, o); toSlot(1, o); };

function kiteList(slot) {
  const out = [];
  for (const k of kites.values()) if (k.landed) out.push({ id: k.id, pal: k.pal, P: k.P, Q: k.Q, landed: true, mine: k.owner === slot });
  return out;
}

function newClient(conn) {
  let slot = -1, helloTimer = setTimeout(() => conn.end(), 8000), count = 0, t0 = Date.now();
  conn.onclose = () => {
    clearTimeout(helloTimer);
    if (slot >= 0 && players[slot] === conn) { players[slot] = null; last[slot] = null; toSlot(1 - slot, { t: 'peer', on: false }); console.log('saiu:', NAMES[slot]); }
  };
  conn.onmsg = text => {
    const now = Date.now(); if (now - t0 > 1000) { t0 = now; count = 0; } if (++count > 80) return conn.end();
    let m; try { m = JSON.parse(text); } catch (_) { return; }
    if (!m || typeof m.t !== 'string') return;
    if (slot < 0) {
      if (m.t !== 'hello') return;
      const inv = String(m.inv || ''); let s = -1;
      for (let i = 0; i < 2; i++) if (safeEq(inv, TOKENS[i])) s = i;
      if (s < 0) { conn.text(JSON.stringify({ t: 'err', m: 'Convite inválido. Peça o link de novo.', fatal: true })); setTimeout(() => conn.end(), 200); return; }
      clearTimeout(helloTimer);
      const old = players[s]; if (old && old !== conn) { old.onclose = null; old.text(JSON.stringify({ t: 'err', m: 'Este convite entrou em outro aparelho.', fatal: true })); setTimeout(() => old.end(), 200); }
      slot = s; players[s] = conn; last[s] = null;
      conn.text(JSON.stringify({ t: 'welcome', uid: s + 1, slot: s, name: NAMES[s], peer: peerInfo(s), kites: kiteList(s) }));
      toSlot(1 - s, { t: 'peer', on: true, slot: s, name: NAMES[s] });
      console.log('entrou:', NAMES[s]);
      return;
    }
    if (players[slot] !== conn) return;
    const other = 1 - slot;
    switch (m.t) {
      case 's': {
        if (!nums(m.p, 4) || !Array.isArray(m.k) || m.k.length !== 11 || !m.k.every(num)) return;
        const o = { t: 's', p: m.p, k: m.k };
        if (Array.isArray(m.r) && m.r.length <= 300 && m.r.length % 3 === 0 && m.r.every(num)) o.r = m.r;
        if (nums(m.pin, 3)) o.pin = m.pin;
        if (validPal(m.pal)) o.pal = m.pal;
        last[slot] = { p: m.p, k: m.k };
        toSlot(other, o);
        break; }
      case 'cut': {
        const L = last[slot], O = last[other];
        const ok = players[other] && L && O && L.k[0] === 1 && O.k[0] === 1 && L.k[1] === m.id && num(m.id) && num(m.seg);
        if (!ok) { conn.text(JSON.stringify({ t: 'deny', t2: 'cut', r: 'invalido' })); return; }
        kites.set(m.id, { id: m.id, pal: validPal(m.pal) ? m.pal : [0xff4fa0, 0xffffff, 0xff4fa0, 0xffffff], owner: slot, landed: false, P: null, Q: null });
        last[slot] = { p: L.p, k: [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0] };
        toBoth({ t: 'cutok', by: slot, seg: m.seg });
        break; }
      case 'land': {
        const k = kites.get(m.id);
        if (!k || k.owner !== slot || !nums(m.P, 3) || !nums(m.Q, 4)) return;
        k.landed = true; k.P = m.P; k.Q = m.Q;
        toBoth({ t: 'landed', id: k.id, pal: k.pal, P: k.P, Q: k.Q });
        break; }
      case 'claim': {
        const k = kites.get(m.id), L = last[slot];
        if (!k || !k.landed) { conn.text(JSON.stringify({ t: 'deny', t2: 'claim', r: 'ocupada' })); return; }
        if (L && Math.hypot(L.p[0] - k.P[0], L.p[2] - k.P[2]) > 6) { conn.text(JSON.stringify({ t: 'deny', t2: 'claim', r: 'longe demais' })); return; }
        kites.delete(k.id);
        toBoth({ t: 'claimed', id: k.id, by: slot, pal: k.pal });
        break; }
    }
  };
}

setInterval(() => { for (const c of players) if (c) c.send(0x9, Buffer.alloc(0)); }, 20000);

server.listen(PORT, () => {
  console.log('COMBATXIS no ar na porta', PORT);
  if (!process.env.ADMIN_KEY) console.log('Convites temporarios: /convites?k=' + ADMIN_KEY);
});
