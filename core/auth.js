'use strict';
const crypto = require('crypto');
const store = require('./store');
const mailer = require('./mailer');

const DAILY_LIMIT = Math.max(1, parseInt(process.env.DAILY_LIMIT, 10) || 500);
const DEV_KEY = process.env.DEV_API_KEY || 'WanzzGantengBanget3369';
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const DEV_USERNAME = (process.env.DEV_USERNAME || 'wanz').trim().toLowerCase();
// Bawaan untuk repo PRIVATE. Kalau repo jadi publik, hapus nilai bawaan ini dan pakai environment variable.
const DEV_PASSWORD = process.env.DEV_PASSWORD || 'wanzzXcodeJava356*#';
const DEV_SUB = 'dev:' + DEV_USERNAME;
const DEV_EMAILS = (process.env.DEV_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const INTERNAL_KEY = crypto.randomBytes(24).toString('hex'); // dipakai plugin lama, tidak pernah keluar server

// Bawaan tetap supaya login tidak hilang saat restart/di Vercel. Override lewat SESSION_SECRET.
const SESSION_SECRET = process.env.SESSION_SECRET || 'b9b2d5a6139a84f3b6782ae8935b5533909ba0eeed4263598a7d53a74dcd8164';

// ---------- OTP (verifikasi email saat daftar manual) ----------
// Set OTP_ENABLED=false untuk mematikan (akun langsung jadi tanpa verifikasi)
const OTP_ENABLED = String(process.env.OTP_ENABLED || 'true').toLowerCase() !== 'false';
const OTP_TTL = 600;        // kode berlaku 10 menit
const OTP_RESEND_GAP = 60;  // jeda kirim ulang (detik)
const OTP_MAX_TRIES = 5;    // salah input maksimal
const OTP_MAX_SENDS = 4;    // total kirim email per pendaftaran

const KEY_RE = /^Api-[A-Za-z0-9]{8,40}-wanz$/;
const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const COOKIE = 'wanz_session';
const SESSION_TTL = 30 * 24 * 3600;
const OPEN_PATHS = new Set(['/api/', '/api/logo-proxy', '/api/stats']);

// ---------- util ----------
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const b64u = s => Buffer.from(s).toString('base64url');
const hmac = s => crypto.createHmac('sha256', SESSION_SECRET).update(s).digest('base64url');

const newCode = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');
const otpHash = (email, code) => hmac('otp:' + email + ':' + code);
const ttlLeft = p => Math.max(1, Math.ceil((p.exp - Date.now()) / 1000));

function generateApiKey() {
  let s;
  do {
    s = Array.from({ length: 16 }, () => ALNUM[crypto.randomInt(ALNUM.length)]).join('');
  } while (!/[A-Za-z]/.test(s) || !/[0-9]/.test(s)); // wajib ada huruf dan angka
  return `Api-${s}-wanz`;
}
async function uniqueKey() {
  for (let i = 0; i < 5; i++) {
    const k = generateApiKey();
    if (!(await store.getUserByKey(k))) return k;
  }
  throw new Error('Gagal membuat apikey unik');
}

// Dev hanya untuk email Google yang sudah terverifikasi (akun manual tidak pernah dev)
const devUser = () => ({ sub: DEV_SUB, email: DEV_USERNAME, name: 'Wanz', picture: '', apikey: DEV_KEY });
const isDevUser = u => !!u && (u.sub === DEV_SUB ||
  (!String(u.sub).startsWith('local:') && !!u.email && DEV_EMAILS.includes(u.email.toLowerCase())));

// ---------- password (scrypt bawaan Node) ----------
const scrypt = (pw, salt) => new Promise((ok, no) =>
  crypto.scrypt(pw, salt, 32, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? no(e) : ok(k))));
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return 's1$' + salt.toString('hex') + '$' + (await scrypt(pw, salt)).toString('hex');
}
async function checkPassword(pw, stored) {
  const [v, s, h] = String(stored || '').split('$');
  if (v !== 's1' || !s || !h) { await scrypt(pw, Buffer.alloc(16)); return false; } // samakan waktu
  const k = await scrypt(pw, Buffer.from(s, 'hex'));
  const hb = Buffer.from(h, 'hex');
  return hb.length === k.length && crypto.timingSafeEqual(hb, k);
}
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;

// Hari limit mengikuti WIB (UTC+7), reset 00:00 WIB
const wibNow = () => Date.now() + 7 * 3600e3;
const today = () => new Date(wibNow()).toISOString().slice(0, 10);
const secondsToReset = () => Math.ceil(((Math.floor(wibNow() / 86400e3) + 1) * 86400e3 - wibNow()) / 1000);

const lastDays = n => Array.from({ length: n }, (_, i) =>
  new Date(wibNow() - (n - 1 - i) * 86400e3).toISOString().slice(0, 10));

// ---------- session ----------
function signSession(sub) {
  const body = b64u(JSON.stringify({ sub, exp: Math.floor(Date.now() / 1000) + SESSION_TTL }));
  return body + '.' + hmac(body);
}
function readSession(req) {
  const m = (req.headers.cookie || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig || !safeEqual(sig, hmac(body))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() / 1000 ? p : null;
  } catch (_) { return null; }
}
function setCookie(req, res, value, maxAge) {
  res.setHeader('Set-Cookie',
    `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${req.secure ? '; Secure' : ''}`);
}

// ---------- Google ----------
async function defaultVerifier(idToken) {
  const axios = require('axios');
  const r = await axios.get('https://oauth2.googleapis.com/tokeninfo', {
    params: { id_token: idToken }, timeout: 10000, validateStatus: () => true
  });
  const d = r.data || {};
  if (r.status !== 200) throw new Error('Token Google tidak valid');
  if (d.aud !== GOOGLE_CLIENT_ID) throw new Error('Client ID tidak cocok');
  if (!['accounts.google.com', 'https://accounts.google.com'].includes(d.iss)) throw new Error('Issuer salah');
  if (String(d.email_verified) !== 'true') throw new Error('Email Google belum terverifikasi');
  return { sub: String(d.sub), email: d.email, name: d.name || d.email, picture: d.picture || '' };
}
let verifier = defaultVerifier;

// ---------- cache lookup apikey (kurangi hit ke DB) ----------
const keyCache = new Map();
async function lookupKey(key) {
  const c = keyCache.get(key);
  if (c && c.exp > Date.now()) return c.user;
  const user = await store.getUserByKey(key);
  if (user) {
    if (keyCache.size > 5000) keyCache.clear();
    keyCache.set(key, { user, exp: Date.now() + 60000 });
  }
  return user;
}

// ---------- gate semua /api/* ----------
async function apiGate(req, res, next) {
  if (!req.path.startsWith('/api/') || OPEN_PATHS.has(req.path)) return next();

  const q = req.query.apikey;
  const key = String((Array.isArray(q) ? q[0] : q) || req.headers['x-api-key'] || '').trim();
  const fail = (code, error, extra) => res.status(code).json(Object.assign({ status: false, error }, extra));

  if (!key) return fail(401, 'Apikey wajib diisi. Login di /dashboard untuk dapat apikey gratis.');

  try {
    let isDev = false, user = null, uid = DEV_SUB;
    if (safeEqual(key, DEV_KEY)) isDev = true;
    else if (KEY_RE.test(key)) user = await lookupKey(key);
    if (!isDev && !user) return fail(401, 'Apikey invalid atau tidak terdaftar');
    if (isDevUser(user)) { isDev = true; uid = user.sub; }

    if (isDev) {
      res.setHeader('X-RateLimit-Limit', 'unlimited');
      store.incrUsage(uid, today()).catch(() => {}); // tidak dibatasi, tapi dicatat untuk grafik
    } else {
      const used = await store.incrUsage(user.sub, today());
      const reset = secondsToReset();
      res.setHeader('X-RateLimit-Limit', DAILY_LIMIT);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, DAILY_LIMIT - used));
      res.setHeader('X-RateLimit-Reset', reset);
      if (used > DAILY_LIMIT) {
        res.setHeader('Retry-After', reset);
        return fail(429, `Limit harian ${DAILY_LIMIT} request sudah habis. Reset 00:00 WIB.`, { resetIn: reset });
      }
    }

    // plugin lama mengecek global.apikey.includes(req.query.apikey); ganti dengan key internal
    Object.defineProperty(req, 'query', {
      value: Object.assign({}, req.query, { apikey: INTERNAL_KEY }),
      writable: true, configurable: true, enumerable: true
    });
    next();
  } catch (e) {
    console.error('[gate]', e.message);
    fail(503, 'Layanan sementara bermasalah, coba lagi sebentar.');
  }
}

// ---------- handler /auth/* ----------
async function mePayload(user) {
  const dev = isDevUser(user);
  const used = await store.getUsage(user.sub, today());
  return {
    status: true,
    user: { email: user.email, name: dev ? 'Wanz' : user.name, picture: user.picture || '' },
    apikey: user.apikey,
    provider: user.sub === DEV_SUB ? 'dev' : String(user.sub).startsWith('local:') ? 'local' : 'google',
    plan: dev ? 'dev' : 'free',
    limit: dev ? null : DAILY_LIMIT,
    used: dev ? used : Math.min(used, DAILY_LIMIT),
    remaining: dev ? null : Math.max(0, DAILY_LIMIT - used),
    resetIn: secondsToReset(),
    createdAt: user.createdAt || null
  };
}
async function sessionUser(req, res) {
  const s = readSession(req);
  const user = s && (s.sub === DEV_SUB ? (DEV_PASSWORD ? devUser() : null) : await store.getUserBySub(s.sub));
  if (!user) {
    res.status(401).json({ status: false, error: 'Belum login' });
    return null;
  }
  return user;
}

const devLock = { fails: 0, until: 0 };
async function devLogin(req, res, pw) {
  if (Date.now() < devLock.until) return res.status(429).json({ status: false, error: 'Terlalu banyak percobaan, coba lagi nanti.' });
  const ok = !!DEV_PASSWORD && pw.length <= 128 && safeEqual(pw, DEV_PASSWORD);
  if (!ok) {
    if (++devLock.fails >= 10) { devLock.until = Date.now() + 15 * 60e3; devLock.fails = 0; }
    return res.status(401).json({ status: false, error: 'Email atau password salah' });
  }
  devLock.fails = 0;
  setCookie(req, res, signSession(DEV_SUB), SESSION_TTL);
  res.setHeader('Cache-Control', 'no-store');
  res.json(await mePayload(devUser()));
}

async function createLocalUser(req, res, { name, email, passHash }) {
  const now = new Date().toISOString();
  const user = {
    sub: 'local:' + crypto.randomBytes(12).toString('hex'), email, name, picture: '',
    passHash, emailVerified: OTP_ENABLED, apikey: await uniqueKey(), createdAt: now, lastLogin: now
  };
  await store.saveUser(user);
  setCookie(req, res, signSession(user.sub), SESSION_TTL);
  res.setHeader('Cache-Control', 'no-store');
  res.json(await mePayload(user));
}

const handlers = {
  config(req, res) {
    res.json({ status: true, googleClientId: GOOGLE_CLIENT_ID, dailyLimit: DAILY_LIMIT, loginReady: !!GOOGLE_CLIENT_ID, otpRequired: OTP_ENABLED });
  },
  async google(req, res) {
    if (!GOOGLE_CLIENT_ID) return res.status(503).json({ status: false, error: 'Login Google belum dikonfigurasi (GOOGLE_CLIENT_ID kosong)' });
    const cred = req.body && req.body.credential;
    if (typeof cred !== 'string' || cred.length < 20 || cred.length > 4096) {
      return res.status(400).json({ status: false, error: "Field 'credential' tidak valid" });
    }
    let p;
    try { p = await verifier(cred); }
    catch (e) { return res.status(401).json({ status: false, error: 'Login Google gagal: ' + e.message }); }

    const now = new Date().toISOString();
    let user = await store.getUserBySub(p.sub);
    if (user) Object.assign(user, { email: p.email, name: p.name, picture: p.picture, lastLogin: now }); // nama selalu ikut akun Gmail
    else user = { sub: p.sub, email: p.email, name: p.name, picture: p.picture, apikey: await uniqueKey(), createdAt: now, lastLogin: now };
    await store.saveUser(user);

    setCookie(req, res, signSession(user.sub), SESSION_TTL);
    res.setHeader('Cache-Control', 'no-store');
    res.json(await mePayload(user));
  },
  async register(req, res) {
    const b = req.body || {};
    const name = String(b.name || '').replace(/\s+/g, ' ').trim();
    const email = String(b.email || '').trim().toLowerCase();
    const pw = String(b.password || '');
    const bad = m => res.status(400).json({ status: false, error: m });
    if (name.length < 2 || name.length > 40) return bad('Nama harus 2 sampai 40 karakter');
    if (name.toLowerCase().replace(/\s/g, '') === DEV_USERNAME) return bad('Nama ini dicadangkan, pakai nama lain');
    if (email.length > 100 || !EMAIL_RE.test(email)) return bad('Format email tidak valid');
    if (pw.length < 8 || pw.length > 128) return bad('Password minimal 8 karakter');
    if (await store.getUserByEmail(email)) {
      return res.status(409).json({ status: false, error: 'Email sudah terdaftar. Silakan masuk (atau pakai tombol Google kalau daftar lewat Google).' });
    }
    const passHash = await hashPassword(pw);

    // OTP dimatikan: langsung buat akun seperti sebelumnya
    if (!OTP_ENABLED) return createLocalUser(req, res, { name, email, passHash });

    if (!mailer.ready) {
      return res.status(503).json({ status: false, error: 'Pengiriman email belum dikonfigurasi di server (lihat .env.example).' });
    }
    const old = await store.getPending(email);
    const now = Date.now();
    if (old && now - old.lastSent < OTP_RESEND_GAP * 1000) {
      const wait = Math.ceil((OTP_RESEND_GAP * 1000 - (now - old.lastSent)) / 1000);
      return res.status(429).json({ status: false, error: `Tunggu ${wait} detik sebelum minta kode lagi`, resendIn: wait });
    }
    if (old && old.sends >= OTP_MAX_SENDS) {
      return res.status(429).json({ status: false, error: 'Batas pengiriman kode tercapai, coba lagi beberapa menit lagi' });
    }
    const code = newCode();
    const rec = { name, email, passHash, codeHash: otpHash(email, code), sends: old ? old.sends + 1 : 1, lastSent: now, exp: now + OTP_TTL * 1000 };
    await store.setPending(email, rec, OTP_TTL);
    try {
      await mailer.sendOtp(email, name, code, OTP_TTL / 60);
    } catch (e) {
      console.error('[otp] kirim gagal:', e.message);
      if (old) await store.setPending(email, old, ttlLeft(old)); else await store.delPending(email);
      return res.status(502).json({ status: false, error: 'Gagal mengirim email kode. Coba lagi atau hubungi admin.' });
    }
    res.setHeader('Cache-Control', 'no-store');
    res.json({ status: true, otpRequired: true, email, expiresIn: OTP_TTL, resendIn: OTP_RESEND_GAP });
  },
  async verifyOtp(req, res) {
    const b = req.body || {};
    const email = String(b.email || '').trim().toLowerCase();
    const code = String(b.code || '').replace(/\s/g, '');
    const fail = (c, m) => res.status(c).json({ status: false, error: m });
    if (email.length > 100 || !/^\d{6}$/.test(code)) return fail(400, 'Kode harus 6 digit angka');
    const p = await store.getPending(email);
    if (!p || p.exp < Date.now()) return fail(400, 'Kode kedaluwarsa atau belum diminta. Silakan daftar ulang.');
    const tries = await store.incrTries(email, ttlLeft(p)); // atomik, dihitung sebelum dicocokkan
    if (tries > OTP_MAX_TRIES) {
      await store.delPending(email);
      return fail(429, 'Terlalu banyak salah input. Silakan daftar ulang.');
    }
    if (!safeEqual(otpHash(email, code), p.codeHash)) {
      const left = OTP_MAX_TRIES - tries;
      if (left <= 0) { await store.delPending(email); return fail(429, 'Terlalu banyak salah input. Silakan daftar ulang.'); }
      return fail(401, `Kode salah. Sisa percobaan: ${left}`);
    }
    if (await store.getUserByEmail(email)) { await store.delPending(email); return fail(409, 'Email sudah terdaftar. Silakan masuk.'); }
    await store.delPending(email);
    return createLocalUser(req, res, { name: p.name, email: p.email, passHash: p.passHash });
  },
  async resendOtp(req, res) {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const fail = (c, m, extra) => res.status(c).json(Object.assign({ status: false, error: m }, extra));
    const p = email.length <= 100 ? await store.getPending(email) : null;
    if (!p) return fail(400, 'Tidak ada pendaftaran yang menunggu. Silakan daftar ulang.');
    const now = Date.now();
    if (now - p.lastSent < OTP_RESEND_GAP * 1000) {
      const wait = Math.ceil((OTP_RESEND_GAP * 1000 - (now - p.lastSent)) / 1000);
      return fail(429, `Tunggu ${wait} detik sebelum kirim ulang`, { resendIn: wait });
    }
    if (p.sends >= OTP_MAX_SENDS) return fail(429, 'Batas kirim ulang tercapai. Daftar ulang beberapa menit lagi.');
    const code = newCode();
    const rec = Object.assign({}, p, { codeHash: otpHash(email, code), sends: p.sends + 1, lastSent: now, exp: now + OTP_TTL * 1000 });
    await store.setPending(email, rec, OTP_TTL);
    try {
      await mailer.sendOtp(email, p.name, code, OTP_TTL / 60);
    } catch (e) {
      console.error('[otp] kirim ulang gagal:', e.message);
      await store.setPending(email, p, ttlLeft(p));
      return fail(502, 'Gagal mengirim email kode. Coba lagi nanti.');
    }
    res.json({ status: true, expiresIn: OTP_TTL, resendIn: OTP_RESEND_GAP });
  },
  async login(req, res) {
    const b = req.body || {};
    const email = String(b.email || '').trim().toLowerCase();
    const pw = String(b.password || '');
    if (email === DEV_USERNAME) return devLogin(req, res, pw);
    const user = email.length <= 100 && pw.length <= 128 ? await store.getUserByEmail(email) : null;
    const ok = await checkPassword(pw, user && user.passHash);
    if (!user || !ok) {
      if (user && !user.passHash) {
        return res.status(401).json({ status: false, error: 'Akun ini terdaftar lewat Google. Masuk dengan tombol Google.' });
      }
      return res.status(401).json({ status: false, error: 'Email atau password salah' });
    }
    user.lastLogin = new Date().toISOString();
    await store.saveUser(user);
    setCookie(req, res, signSession(user.sub), SESSION_TTL);
    res.setHeader('Cache-Control', 'no-store');
    res.json(await mePayload(user));
  },
  async usage(req, res) {
    const user = await sessionUser(req, res);
    if (!user) return;
    const n = Math.min(30, Math.max(1, parseInt(req.query.days, 10) || 14));
    const dev = isDevUser(user);
    const days = lastDays(n);
    const counts = await store.getUsageRange(user.sub, days);
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      status: true,
      limit: dev ? null : DAILY_LIMIT,
      series: days.map((date, i) => ({ date, count: dev ? counts[i] : Math.min(counts[i], DAILY_LIMIT) }))
    });
  },
  async me(req, res) {
    const user = await sessionUser(req, res);
    if (!user) return;
    res.setHeader('Cache-Control', 'no-store');
    res.json(await mePayload(user));
  },
  async regenerate(req, res) {
    const user = await sessionUser(req, res);
    if (!user) return;
    if (user.sub === DEV_SUB) return res.status(400).json({ status: false, error: 'Apikey dev diatur lewat environment DEV_API_KEY' });
    keyCache.delete(user.apikey);
    await store.rotateKey(user, await uniqueKey()); // kuota dihitung per akun, jadi ganti key tidak mereset limit
    res.setHeader('Cache-Control', 'no-store');
    res.json(await mePayload(user));
  },
  logout(req, res) {
    setCookie(req, res, '', 0);
    res.json({ status: true });
  }
};

function createRouter() {
  const express = require('express');
  const rateLimit = require('express-rate-limit');
  const r = express.Router();
  const limiter = rateLimit({
    windowMs: 60000, max: 30, standardHeaders: true, legacyHeaders: false,
    validate: { trustProxy: false },
    message: { status: false, error: 'Terlalu banyak percobaan, coba lagi sebentar.' }
  });
  const wrap = fn => (req, res) => Promise.resolve(fn(req, res)).catch(e => {
    console.error('[auth]', e.message);
    if (!res.headersSent) res.status(500).json({ status: false, error: 'Terjadi kesalahan server' });
  });
  const strict = (max, windowMs) => rateLimit({
    windowMs, max, standardHeaders: true, legacyHeaders: false, validate: { trustProxy: false },
    message: { status: false, error: 'Terlalu banyak percobaan, coba lagi nanti.' }
  });
  r.get('/auth/config', handlers.config);
  r.post('/auth/register', strict(5, 3600e3), wrap(handlers.register));
  r.post('/auth/verify-otp', strict(15, 10 * 60e3), wrap(handlers.verifyOtp));
  r.post('/auth/resend-otp', strict(6, 10 * 60e3), wrap(handlers.resendOtp));
  r.post('/auth/login', strict(10, 60e3), wrap(handlers.login));
  r.post('/auth/google', limiter, wrap(handlers.google));
  const reads = strict(120, 60e3);
  r.get('/auth/me', reads, wrap(handlers.me));
  r.get('/auth/usage', reads, wrap(handlers.usage));
  r.post('/auth/regenerate-key', limiter, wrap(handlers.regenerate));
  r.post('/auth/logout', handlers.logout);
  return r;
}

module.exports = {
  INTERNAL_KEY, DAILY_LIMIT, apiGate, createRouter, handlers,
  generateApiKey, signSession, readSession,
  _setVerifier: f => { verifier = f; }
};
