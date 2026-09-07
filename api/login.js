// api/login.js
// Login sekarang mengecek ke Vercel KV (database), BUKAN ke environment
// variable statis lagi. Supaya ada akun pertama untuk masuk, endpoint ini
// otomatis membuat SATU akun admin dari env var ADMIN_USERNAME/ADMIN_PASSWORD
// kalau database user masih kosong (baru pertama kali deploy). Setelah itu,
// admin tersebut yang menambah/menghapus user lain lewat panel Admin di
// dalam tool — owner tool ini (kamu) tidak perlu pegang akses Vercel lagi
// untuk urusan tambah/hapus user harian.

const {
  kvSetJSON, kvGetJSON, kvSadd, kvSmembers,
  USERS_SET_KEY, userKey,
  hashPassword, verifyPassword,
  makeToken, parseBody
} = require('./_lib');

async function ensureBootstrapAdmin() {
  const existing = await kvSmembers(USERS_SET_KEY);
  if (existing.length > 0) return;

  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !password) return; // belum diset, biarkan login gagal wajar

  const record = {
    username,
    passwordHash: hashPassword(password),
    role: 'admin',
    createdAt: Date.now()
  };
  await kvSetJSON(userKey(username), record);
  await kvSadd(USERS_SET_KEY, username);
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const { username, password } = parseBody(req);
  if (!username || !password) {
    res.status(400).json({ error: 'Username dan password wajib diisi.' });
    return;
  }

  try {
    await ensureBootstrapAdmin();

    const record = await kvGetJSON(userKey(username));
    if (!record || !verifyPassword(password, record.passwordHash)) {
      res.status(401).json({ error: 'Username atau password salah.' });
      return;
    }

    const token = makeToken(record.username, record.role);
    res.status(200).json({ token, username: record.username, role: record.role });
  } catch (e) {
    res.status(500).json({ error: 'Gagal memproses login: ' + e.message });
  }
};
