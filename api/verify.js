// api/verify.js
// Dipanggil tiap kali index.html dibuka untuk memastikan token sesi masih
// sah (signature + belum expired) DAN user-nya masih ada di database KV saat
// ini — jadi begitu admin hapus seorang user lewat panel, sesi lama orang itu
// langsung invalid di request berikutnya, bukan menunggu 12 jam.

const { kvGetJSON, userKey, decodeToken, parseBody } = require('./_lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(200).json({ valid: false });
    return;
  }

  const { token } = parseBody(req);
  if (!token) {
    res.status(200).json({ valid: false });
    return;
  }

  const decoded = decodeToken(token);
  if (!decoded.validSignature || !decoded.notExpired) {
    res.status(200).json({ valid: false });
    return;
  }

  try {
    const record = await kvGetJSON(userKey(decoded.username));
    if (!record) {
      res.status(200).json({ valid: false });
      return;
    }
    res.status(200).json({ valid: true, username: record.username, role: record.role });
  } catch (e) {
    res.status(200).json({ valid: false });
  }
};
