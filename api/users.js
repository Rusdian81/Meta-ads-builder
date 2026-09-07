// api/users.js
// Endpoint pengelolaan user, HANYA bisa dipanggil oleh yang login sebagai
// admin (dicek lewat requireAdmin di _lib.js, via header Authorization).
// Dipanggil oleh panel "Admin" di dalam index.html — inilah yang membuat
// pembeli tool bisa tambah/hapus/reset user stafnya sendiri tanpa perlu
// masuk ke dashboard Vercel.

const {
  kvSetJSON, kvGetJSON, kvDel, kvSadd, kvSrem, kvSmembers,
  USERS_SET_KEY, userKey,
  hashPassword, parseBody, requireAdmin
} = require('./_lib');

async function countAdmins() {
  const usernames = await kvSmembers(USERS_SET_KEY);
  const records = await Promise.all(usernames.map((u) => kvGetJSON(userKey(u))));
  return records.filter((r) => r && r.role === 'admin').length;
}

module.exports = async (req, res) => {
  const auth = await requireAdmin(req);
  if (!auth.ok) {
    res.status(auth.status).json({ error: auth.error });
    return;
  }

  try {
    if (req.method === 'GET') {
      const usernames = await kvSmembers(USERS_SET_KEY);
      const records = await Promise.all(usernames.map((u) => kvGetJSON(userKey(u))));
      const list = records
        .filter(Boolean)
        .map((r) => ({ username: r.username, role: r.role, createdAt: r.createdAt }));
      res.status(200).json({ users: list });
      return;
    }

    if (req.method === 'POST') {
      const { username, password, role } = parseBody(req);
      if (!username || !password) {
        res.status(400).json({ error: 'Username dan password wajib diisi.' });
        return;
      }
      const existing = await kvGetJSON(userKey(username));
      if (existing) {
        res.status(409).json({ error: 'Username sudah dipakai.' });
        return;
      }
      const record = {
        username,
        passwordHash: hashPassword(password),
        role: role === 'admin' ? 'admin' : 'member',
        createdAt: Date.now()
      };
      await kvSetJSON(userKey(username), record);
      await kvSadd(USERS_SET_KEY, username);
      res.status(200).json({ ok: true });
      return;
    }

    if (req.method === 'PATCH') {
      const { username, newPassword, newRole } = parseBody(req);
      if (!username) {
        res.status(400).json({ error: 'Username wajib diisi.' });
        return;
      }
      const existing = await kvGetJSON(userKey(username));
      if (!existing) {
        res.status(404).json({ error: 'User tidak ditemukan.' });
        return;
      }
      if (newRole && newRole !== 'admin' && existing.role === 'admin') {
        const adminCount = await countAdmins();
        if (adminCount <= 1) {
          res.status(400).json({ error: 'Tidak bisa menurunkan admin terakhir. Tambah admin lain dulu.' });
          return;
        }
      }
      const updated = {
        ...existing,
        passwordHash: newPassword ? hashPassword(newPassword) : existing.passwordHash,
        role: newRole === 'admin' ? 'admin' : newRole === 'member' ? 'member' : existing.role
      };
      await kvSetJSON(userKey(username), updated);
      res.status(200).json({ ok: true });
      return;
    }

    if (req.method === 'DELETE') {
      const { username } = parseBody(req);
      if (!username) {
        res.status(400).json({ error: 'Username wajib diisi.' });
        return;
      }
      const existing = await kvGetJSON(userKey(username));
      if (!existing) {
        res.status(404).json({ error: 'User tidak ditemukan.' });
        return;
      }
      if (existing.role === 'admin') {
        const adminCount = await countAdmins();
        if (adminCount <= 1) {
          res.status(400).json({ error: 'Tidak bisa menghapus admin terakhir.' });
          return;
        }
      }
      await kvDel(userKey(username));
      await kvSrem(USERS_SET_KEY, username);
      res.status(200).json({ ok: true });
      return;
    }

    res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    res.status(500).json({ error: 'Gagal memproses: ' + e.message });
  }
};
