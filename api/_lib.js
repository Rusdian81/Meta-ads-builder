// api/_lib.js
// File internal (BUKAN endpoint — nama diawali underscore supaya Vercel tidak
// menjadikannya route). Isinya dipakai bareng oleh login.js, verify.js, users.js.

const crypto = require('crypto');

/* ---------------------------------------------------------
   VERCEL KV (Upstash REST API) — tanpa perlu npm package
--------------------------------------------------------- */
function kvBase() {
  const url = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!url || !token) {
    throw new Error(
      'KV belum terhubung. Buka Vercel Dashboard -> project ini -> tab Storage -> Create Database -> KV -> Connect ke project ini, lalu redeploy.'
    );
  }
  return { url, token };
}

async function kvCall(pathParts) {
  const { url, token } = kvBase();
  const path = pathParts.map((p) => encodeURIComponent(p)).join('/');
  const res = await fetch(`${url}/${path}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error(`KV error ${res.status}`);
  const data = await res.json();
  return data.result;
}

async function kvSetJSON(key, valueObj) {
  const { url, token } = kvBase();
  const res = await fetch(`${url}/set/${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify(valueObj)
  });
  if (!res.ok) throw new Error(`KV error ${res.status}`);
}

async function kvGetJSON(key) {
  const result = await kvCall(['get', key]);
  if (result === null || result === undefined) return null;
  try { return JSON.parse(result); } catch (e) { return null; }
}

async function kvDel(key) {
  return kvCall(['del', key]);
}

async function kvSadd(setKey, member) {
  return kvCall(['sadd', setKey, member]);
}

async function kvSrem(setKey, member) {
  return kvCall(['srem', setKey, member]);
}

async function kvSmembers(setKey) {
  const result = await kvCall(['smembers', setKey]);
  return Array.isArray(result) ? result : [];
}

const USERS_SET_KEY = 'lpforge:users:all';
const userKey = (username) => `lpforge:user:${username}`;

/* ---------------------------------------------------------
   PASSWORD HASHING (scrypt, bawaan Node, tanpa dependency)
--------------------------------------------------------- */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch (e) {
    return false;
  }
}

/* ---------------------------------------------------------
   SESSION TOKEN (HMAC, bawaan Node, tanpa dependency)
--------------------------------------------------------- */
function getSecret() {
  return process.env.LP_FORGE_SECRET || 'ganti-secret-ini-lewat-env-var-LP_FORGE_SECRET';
}

function sign(payload) {
  return crypto.createHmac('sha256', getSecret()).update(payload).digest('hex');
}

const SESSION_DURATION_MS = 1000 * 60 * 60 * 12; // 12 jam

function makeToken(username, role) {
  const expires = Date.now() + SESSION_DURATION_MS;
  const payload = `${username}:${role}:${expires}`;
  const signature = sign(payload);
  return Buffer.from(`${payload}:${signature}`).toString('base64');
}

function decodeToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts = decoded.split(':');
    const signature = parts.pop();
    const expires = parts.pop();
    const role = parts.pop();
    const username = parts.join(':');
    const expected = sign(`${username}:${role}:${expires}`);
    const validSignature = expected === signature;
    const notExpired = Date.now() < Number(expires);
    return { validSignature, notExpired, username, role, expires: Number(expires) };
  } catch (e) {
    return { validSignature: false, notExpired: false };
  }
}

function parseBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch (e) { return {}; }
  }
  return {};
}

function getBearerToken(req) {
  const header = req.headers && req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length).trim();
}

/**
 * Validasi token dari header Authorization DAN pastikan user masih
 * terdaftar di KV dengan role admin. Dipakai untuk melindungi endpoint
 * pengelolaan user (api/users.js).
 */
async function requireAdmin(req) {
  const token = getBearerToken(req);
  if (!token) return { ok: false, status: 401, error: 'Token tidak ada.' };
  const decoded = decodeToken(token);
  if (!decoded.validSignature || !decoded.notExpired) {
    return { ok: false, status: 401, error: 'Sesi tidak valid atau sudah habis.' };
  }
  const record = await kvGetJSON(userKey(decoded.username));
  if (!record) return { ok: false, status: 401, error: 'User tidak ditemukan lagi.' };
  if (record.role !== 'admin') return { ok: false, status: 403, error: 'Bukan admin.' };
  return { ok: true, username: decoded.username };
}

module.exports = {
  kvSetJSON, kvGetJSON, kvDel, kvSadd, kvSrem, kvSmembers,
  USERS_SET_KEY, userKey,
  hashPassword, verifyPassword,
  makeToken, decodeToken,
  parseBody, getBearerToken, requireAdmin
};
