// api/login.js
// Endpoint login untuk LP Forge. Daftar user diatur OWNER lewat environment
// variable LP_FORGE_USERS di dashboard Vercel (Project Settings -> Environment
// Variables), bukan oleh user itu sendiri (tidak ada self-register).
//
// Format LP_FORGE_USERS (JSON string), contoh:
// [{"username":"budi","password":"passwordBudi123"},{"username":"sinta","password":"passwordSinta456"}]
//
// Set juga LP_FORGE_SECRET (string acak apapun, bebas, cukup panjang) untuk
// menandatangani token sesi. WAJIB diganti dari default sebelum dipakai serius.

const crypto = require('crypto');

const SESSION_DURATION_MS = 1000 * 60 * 60 * 12; // 12 jam

function getUsers() {
  const raw = process.env.LP_FORGE_USERS;
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      // biarkan fallback di bawah kalau JSON di env var salah format
    }
  }
  // FALLBACK CONTOH — hanya aktif kalau LP_FORGE_USERS belum diset di Vercel.
  // GANTI atau HAPUS ini setelah owner mengatur LP_FORGE_USERS yang sebenarnya.
  return [
    { username: 'owner', password: 'ganti-password-ini' }
  ];
}

function getSecret() {
  return process.env.LP_FORGE_SECRET || 'ganti-secret-ini-lewat-env-var-LP_FORGE_SECRET';
}

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function parseBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch (e) { return {}; }
  }
  return {};
}

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const { username, password } = parseBody(req);
  if (!username || !password) {
    res.status(400).json({ error: 'Username dan password wajib diisi.' });
    return;
  }

  const users = getUsers();
  const found = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!found) {
    res.status(401).json({ error: 'Username atau password salah.' });
    return;
  }

  const expires = Date.now() + SESSION_DURATION_MS;
  const payload = `${username}:${expires}`;
  const signature = sign(payload, getSecret());
  const token = Buffer.from(`${payload}:${signature}`).toString('base64');

  res.status(200).json({ token, username, expires });
};
