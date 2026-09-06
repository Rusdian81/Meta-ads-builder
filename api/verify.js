// api/verify.js
// Dipanggil setiap kali index.html dibuka, untuk memastikan token sesi yang
// tersimpan di browser masih sah (belum expired & tidak dipalsukan) sebelum
// menampilkan tool-nya. Tidak butuh database — validasi murni lewat HMAC.

const crypto = require('crypto');

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
    res.status(405).json({ valid: false });
    return;
  }

  const { token } = parseBody(req);
  if (!token) {
    res.status(200).json({ valid: false });
    return;
  }

  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts = decoded.split(':');
    const signature = parts.pop();
    const expires = parts.pop();
    const username = parts.join(':');

    const expected = sign(`${username}:${expires}`, getSecret());
    const validSignature = expected === signature;
    const notExpired = Date.now() < Number(expires);

    if (validSignature && notExpired) {
      res.status(200).json({ valid: true, username });
    } else {
      res.status(200).json({ valid: false });
    }
  } catch (e) {
    res.status(200).json({ valid: false });
  }
};
