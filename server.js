require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('./db');
const archiver = require('archiver');

db.exec(`
CREATE TABLE IF NOT EXISTS exports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  month TEXT NOT NULL,
  category TEXT NOT NULL,
  file_count INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('Missing SESSION_SECRET in the .env file. See Step 6a.');
  process.exit(1);
}

const PORT = Number(process.env.PORT) || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const QUOTA = (Number(process.env.STORAGE_QUOTA_GB) || 10) * 1024 ** 3;
const MAX_FILE = 200 * 1024 * 1024;
const CATEGORIES = ['Aircon', 'Washing Machine', 'Refrigerator'];

const app = express();
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'SAMEORIGIN');
  res.set('Referrer-Policy', 'same-origin');
  next();
});
app.use(express.json());
app.use(session({
  name: 'ecoleon.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Everything except the login page requires a signed-in user
app.use((req, res, next) => {
  const open = ['/login.html', '/api/login', '/logo.png'];
  if (req.session.userId || open.includes(req.path)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Please sign in.' });
  res.redirect('/login.html');
});
app.use(express.static(path.join(__dirname, 'public')));

const getUser = req => db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
const publicUser = u => ({
  id: u.id, name: u.name, email: u.email, role: u.role,
  canUpload: !!u.can_upload, canDownload: !!u.can_download, canDelete: !!u.can_delete
});
const allow = flag => (req, res, next) => {
  const u = getUser(req);
  if (u && (u.role === 'admin' || u[flag])) { req.user = u; return next(); }
  res.status(403).json({ error: 'You do not have permission to do this.' });
};

// ---------- Login (locks after 5 wrong tries for 15 minutes) ----------
const attempts = new Map();
const MAX_TRIES = 5, LOCK_MS = 15 * 60 * 1000;

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const em = String(email || '').toLowerCase();
  const key = req.ip + '|' + em;
  const a = attempts.get(key);
  if (a && a.until > Date.now()) {
    const mins = Math.ceil((a.until - Date.now()) / 60000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${mins} minute${mins === 1 ? '' : 's'}.` });
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(em);
  if (!user || !bcrypt.compareSync(String(password || ''), user.password_hash)) {
    const cur = a && a.until === 0 ? a : { count: 0, until: 0 };
    cur.count++;
    if (cur.count >= MAX_TRIES) cur.until = Date.now() + LOCK_MS;
    attempts.set(key, cur);
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }
  attempts.delete(key);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Could not sign in. Please try again.' });
    req.session.userId = user.id;
    res.json(publicUser(user));
  });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => {
  const u = getUser(req);
  if (!u) return res.status(401).json({ error: 'Please sign in.' });
  res.json(publicUser(u));
});
app.post('/api/me/password', (req, res) => {
  const u = getUser(req);
  if (!u) return res.status(401).json({ error: 'Please sign in.' });
  const { current, newPassword } = req.body || {};
  if (!bcrypt.compareSync(String(current || ''), u.password_hash)) {
    return res.status(400).json({ error: 'Your current password is incorrect.' });
  }
  if (String(newPassword || '').length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(String(newPassword), 12), u.id);
  res.json({ ok: true });
});

// ---------- Files ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) =>
      cb(null, crypto.randomUUID() + path.extname(file.originalname).slice(0, 10).replace(/[^.\w]/g, ''))
  }),
  limits: { fileSize: MAX_FILE, files: 20 }
});
const fixName = n => Buffer.from(n, 'latin1').toString('utf8');
const fileById = id => db.prepare('SELECT * FROM files WHERE id = ?').get(id);


app.get('/api/files', (req, res) => {
  const q = '%' + String(req.query.q || '').replace(/[%_\\]/g, '\\$&') + '%';
  const cat = String(req.query.category || '');
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const order = {
    newest: 'f.id DESC', oldest: 'f.id ASC',
    name: 'f.original_name COLLATE NOCASE ASC', largest: 'f.size_bytes DESC'
  }[req.query.sort] || 'f.id DESC';
  const where = `f.original_name LIKE ? ESCAPE '\\' AND (? = '' OR f.category = ?)`;
  const total = db.prepare(`SELECT COUNT(*) AS n FROM files f WHERE ${where}`).get(q, cat, cat).n;
  const files = db.prepare(`
    SELECT f.id, f.original_name, f.category, f.size_bytes, f.uploaded_at, u.name AS uploaded_by
    FROM files f LEFT JOIN users u ON u.id = f.uploaded_by
    WHERE ${where} ORDER BY ${order} LIMIT ? OFFSET ?`).all(q, cat, cat, limit, offset);
  res.json({ files, total });
});
app.post('/api/files', allow('can_upload'), (req, res) => {
  upload.array('files', 20)(req, res, err => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'A file is larger than 200 MB.' : 'Upload failed. Please try again.';
      return res.status(400).json({ error: msg });
    }
    const list = req.files || [];
    if (!list.length) return res.status(400).json({ error: 'Choose at least one file.' });
    const used = db.prepare('SELECT COALESCE(SUM(size_bytes),0) AS n FROM files').get().n;
    const incoming = list.reduce((a, f) => a + f.size, 0);
    if (used + incoming > QUOTA) {
      list.forEach(f => fs.unlink(f.path, () => {}));
      return res.status(413).json({ error: 'Not enough storage space left.' });
    }
    if (!CATEGORIES.includes(req.body.category)) {
      list.forEach(f => fs.unlink(f.path, () => {}));
      return res.status(400).json({ error: 'Choose a category.' });
    }
    const category = req.body.category;
    const ins = db.prepare('INSERT INTO files (original_name, stored_name, category, mime_type, size_bytes, uploaded_by) VALUES (?,?,?,?,?,?)');
    for (const f of list) ins.run(fixName(f.originalname), f.filename, category, f.mimetype, f.size, req.user.id);
    res.json({ uploaded: list.length });
  });
});

app.get('/api/files/:id/download', allow('can_download'), (req, res) => {
  const f = fileById(req.params.id);
  const p = f && path.join(UPLOAD_DIR, f.stored_name);
  if (!f || !fs.existsSync(p)) return res.status(404).json({ error: 'File not found.' });
  res.download(p, f.original_name);
});

app.get('/api/files/:id/view', allow('can_download'), (req, res) => {
  const f = fileById(req.params.id);
  const p = f && path.join(UPLOAD_DIR, f.stored_name);
  if (!f || !fs.existsSync(p)) return res.status(404).json({ error: 'File not found.' });
  if (!/^(application\/pdf|image\/(png|jpe?g|gif|webp))$/.test(f.mime_type || '')) return res.download(p, f.original_name);
  res.sendFile(p, { headers: {
    'Content-Type': f.mime_type,
    'X-Content-Type-Options': 'nosniff',
    'Content-Disposition': "inline; filename*=UTF-8''" + encodeURIComponent(f.original_name)
  } });
});

app.delete('/api/files/:id', allow('can_delete'), (req, res) => {
  const f = fileById(req.params.id);
  if (!f) return res.status(404).json({ error: 'File not found.' });
  db.prepare('DELETE FROM files WHERE id = ?').run(f.id);
  fs.unlink(path.join(UPLOAD_DIR, f.stored_name), () => {});
  res.json({ ok: true });
});

app.get('/api/storage', (req, res) => {
  const t = db.prepare('SELECT COUNT(*) AS files, COALESCE(SUM(size_bytes),0) AS used FROM files').get();
  res.json({ quota: QUOTA, used: t.used, files: t.files });
});

// ---------- Employees (administrators only) ----------
const adminOnly = (req, res, next) => {
  const u = getUser(req);
  if (u && u.role === 'admin') { req.user = u; return next(); }
  res.status(403).json({ error: 'Only administrators can do this.' });
};
const clean = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const adminCount = () => db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get().n;

function userFields(b) {
  const role = b.role === 'admin' ? 'admin' : 'staff';
  const all = role === 'admin';
  return {
    name: clean(b.name), email: clean(b.email, 120).toLowerCase(), role,
    up: all || b.can_upload ? 1 : 0, dl: all || b.can_download ? 1 : 0, de: all || b.can_delete ? 1 : 0
  };
}

app.get('/api/users', adminOnly, (req, res) => {
  res.json(db.prepare(`SELECT id, name, email, role, can_upload, can_download, can_delete, created_at
    FROM users ORDER BY role, name COLLATE NOCASE`).all());
});

app.post('/api/users', adminOnly, (req, res) => {
  const b = req.body || {}, f = userFields(b), pw = String(b.password || '');
  if (!f.name || !f.email) return res.status(400).json({ error: 'Name and email are required.' });
  if (pw.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  try {
    db.prepare(`INSERT INTO users (name, email, password_hash, role, can_upload, can_download, can_delete)
      VALUES (?,?,?,?,?,?,?)`).run(f.name, f.email, bcrypt.hashSync(pw, 12), f.role, f.up, f.dl, f.de);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That email is already in use.' });
    throw e;
  }
});

app.put('/api/users/:id', adminOnly, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Employee not found.' });
  const b = req.body || {}, f = userFields(b), pw = String(b.password || '');
  if (!f.name || !f.email) return res.status(400).json({ error: 'Name and email are required.' });
  if (pw && pw.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (target.role === 'admin' && f.role !== 'admin' && adminCount() <= 1) {
    return res.status(409).json({ error: 'There must be at least one administrator.' });
  }
  try {
    db.prepare('UPDATE users SET name=?, email=?, role=?, can_upload=?, can_download=?, can_delete=? WHERE id=?')
      .run(f.name, f.email, f.role, f.up, f.dl, f.de, target.id);
    if (pw) db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(pw, 12), target.id);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That email is already in use.' });
    throw e;
  }
});

app.delete('/api/users/:id', adminOnly, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Employee not found.' });
  if (target.id === req.user.id) return res.status(409).json({ error: 'You cannot delete your own account.' });
  db.prepare('UPDATE files SET uploaded_by = NULL WHERE uploaded_by = ?').run(target.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  res.json({ ok: true });
});
// ---------- Export and clear (administrators only) ----------
const phTime = s => new Date(new Date(s.replace(' ', 'T') + 'Z').getTime() + 8 * 3600e3)
  .toISOString().slice(0, 16).replace('T', ' ');
const csvCell = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';

// Months follow Philippine time (UTC+8)
function pickFiles(month, category) {
  const m = /^\d{4}-\d{2}$/.test(String(month)) ? String(month) : '';
  const c = CATEGORIES.includes(category) ? category : '';
  const rows = db.prepare(`
    SELECT f.*, u.name AS uploader FROM files f LEFT JOIN users u ON u.id = f.uploaded_by
    WHERE (? = '' OR strftime('%Y-%m', f.uploaded_at, '+8 hours') = ?) AND (? = '' OR f.category = ?)
    ORDER BY f.category, f.uploaded_at`).all(m, m, c, c);
  return { m, c, rows, bytes: rows.reduce((a, f) => a + f.size_bytes, 0) };
}
const wasExported = s => !!db.prepare(`SELECT 1 FROM exports
  WHERE month = ? AND category = ? AND file_count = ? AND total_bytes = ?
  AND created_at >= datetime('now', '-7 days')`).get(s.m || 'all', s.c || 'all', s.rows.length, s.bytes);

app.get('/api/export/months', adminOnly, (req, res) => {
  res.json(db.prepare(`SELECT strftime('%Y-%m', uploaded_at, '+8 hours') AS month,
    COUNT(*) AS files, SUM(size_bytes) AS bytes FROM files GROUP BY month ORDER BY month DESC`).all());
});

app.get('/api/export/summary', adminOnly, (req, res) => {
  const s = pickFiles(req.query.month, req.query.category);
  res.json({ count: s.rows.length, bytes: s.bytes, exported: s.rows.length > 0 && wasExported(s) });
});

app.get('/api/export/download', adminOnly, (req, res) => {
  const s = pickFiles(req.query.month, req.query.category);
  if (!s.rows.length) return res.status(404).json({ error: 'There are no files for this selection.' });

  const name = `ecoleon-files-${s.m || 'all-time'}-${s.c ? s.c.replace(/\s+/g, '-') : 'all-types'}.zip`;
  res.set({ 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="${name}"` });

  const zip = archiver('zip', { store: true }); // files are usually already compressed
  zip.on('error', err => { console.error('Export failed:', err); res.destroy(); });
  res.on('close', () => { if (!res.writableFinished) zip.abort(); });
  res.on('finish', () => {
    db.prepare('INSERT INTO exports (month, category, file_count, total_bytes, created_by) VALUES (?,?,?,?,?)')
      .run(s.m || 'all', s.c || 'all', s.rows.length, s.bytes, req.user.id);
  });
  zip.pipe(res);

  const seen = new Set();
  const entryName = f => {
    const safe = f.original_name.replace(/[\\/:*?"<>|]/g, '_');
    const ext = path.extname(safe), base = safe.slice(0, safe.length - ext.length);
    let n = `${f.category}/${safe}`, i = 2;
    while (seen.has(n.toLowerCase())) n = `${f.category}/${base} (${i++})${ext}`;
    seen.add(n.toLowerCase());
    return n;
  };

  const csv = ['File,Type,Size (bytes),Uploaded (Philippine time),Uploaded by,In ZIP'];
  for (const f of s.rows) {
    const p = path.join(UPLOAD_DIR, f.stored_name), ok = fs.existsSync(p);
    csv.push([f.original_name, f.category, f.size_bytes, phTime(f.uploaded_at), f.uploader || 'Removed user', ok ? 'Yes' : 'MISSING ON DISK'].map(csvCell).join(','));
    if (ok) zip.file(p, { name: entryName(f) });
  }
  zip.append('\ufeff' + csv.join('\r\n'), { name: 'file-list.csv' });
  zip.finalize();
});

app.post('/api/export/clear', adminOnly, (req, res) => {
  const b = req.body || {};
  if (b.confirm !== 'CLEAR') return res.status(400).json({ error: 'Type CLEAR to confirm.' });
  const s = pickFiles(b.month, b.category);
  if (!s.rows.length) return res.status(404).json({ error: 'There are no files for this selection.' });
  if (!wasExported(s)) {
    return res.status(409).json({ error: 'Export these files first. The files changed since the last export, or the export is older than 7 days.' });
  }
  const del = db.prepare('DELETE FROM files WHERE id = ?');
  db.transaction(() => s.rows.forEach(f => del.run(f.id)))();
  s.rows.forEach(f => fs.unlink(path.join(UPLOAD_DIR, f.stored_name), () => {}));
  console.log(`[clear] ${req.user.email} cleared ${s.rows.length} files (${s.bytes} bytes), month=${s.m || 'all'}, type=${s.c || 'all'}`);
  res.json({ cleared: s.rows.length, bytes: s.bytes });
});
app.listen(PORT, () => console.log(`Ecoleon Corporation running at http://localhost:${PORT}`));