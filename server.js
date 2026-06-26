const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

// ── FILE UPLOAD CONFIG ────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const ALLOWED_MIME = new Set([
  'image/gif','image/png','image/jpeg','image/webp',
  'video/mp4',
  'audio/ogg','audio/mpeg','audio/mp3',
]);

const AVATAR_MIME = new Set(['image/gif','image/png','image/jpeg','image/webp']);
const AVATAR_MAX = 5 * 1024 * 1024; // 5 MB

const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `avatar-${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
    },
  }),
  limits: { fileSize: AVATAR_MAX },
  fileFilter: (req, file, cb) => {
    if (AVATAR_MIME.has(file.mimetype)) cb(null, true);
    else cb(new Error('Только изображения для аватара'));
  },
});
const MAX_SIZE = 50 * 1024 * 1024; // 50 MB

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_SIZE },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME.has(file.mimetype)) cb(null, true);
    else cb(new Error('Недопустимый тип файла'));
  },
});

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      bio TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT '';
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      content TEXT,
      attachments JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE posts ADD COLUMN IF NOT EXISTS attachments JSONB DEFAULT '[]';
    CREATE TABLE IF NOT EXISTS likes (
      id SERIAL PRIMARY KEY,
      post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(post_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      attachments JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS attachments JSONB DEFAULT '[]';
  `);
  console.log('✅ Таблицы готовы');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 },
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}

app.get('/api/status', (req, res) => res.json({ ok: true, uptime: process.uptime() }));

// Auth
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Заполни все поля' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hash]
    );
    req.session.userId = rows[0].id;
    res.json({ user: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Имя занято' });
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (!rows[0]) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Неверный логин или пароль' });
    req.session.userId = rows[0].id;
    res.json({ user: { id: rows[0].id, username: rows[0].username } });
  } catch { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, bio, avatar, created_at FROM users WHERE id = $1', [req.session.userId]);
  res.json(rows[0]);
});

// ── FILE UPLOAD ───────────────────────────────────────
app.post('/api/upload', requireAuth, upload.array('files', 10), (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'Нет файлов' });
  const files = req.files.map(f => ({
    url: `/uploads/${f.filename}`,
    name: f.originalname,
    mime: f.mimetype,
    size: f.size,
  }));
  res.json({ files });
});

// ── PROFILE ───────────────────────────────────────────
app.get('/api/profile/:id', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, bio, avatar, created_at FROM users WHERE id = $1',
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json(rows[0]);
});

app.post('/api/profile/bio', requireAuth, async (req, res) => {
  const { bio } = req.body;
  await pool.query('UPDATE users SET bio = $1 WHERE id = $2', [bio || '', req.session.userId]);
  res.json({ ok: true });
});

app.post('/api/profile/avatar', requireAuth, avatarUpload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
  const url = `/uploads/${req.file.filename}`;
  // Delete old avatar file if exists
  const { rows } = await pool.query('SELECT avatar FROM users WHERE id = $1', [req.session.userId]);
  if (rows[0] && rows[0].avatar) {
    const oldPath = path.join(__dirname, 'public', rows[0].avatar);
    if (fs.existsSync(oldPath)) fs.unlink(oldPath, () => {});
  }
  await pool.query('UPDATE users SET avatar = $1 WHERE id = $2', [url, req.session.userId]);
  res.json({ url });
});

// Posts
app.get('/api/posts', async (req, res) => {
  const userId = req.session.userId || 0;
  const { rows } = await pool.query(`
    SELECT p.*, u.username, u.avatar,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes_count,
      (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comments_count,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = $1) AS user_liked
    FROM posts p JOIN users u ON p.user_id = u.id
    ORDER BY p.created_at DESC
  `, [userId]);
  res.json(rows);
});

app.post('/api/posts', requireAuth, async (req, res) => {
  const { title, content, attachments } = req.body;
  if (!title) return res.status(400).json({ error: 'Нужен заголовок' });
  const { rows } = await pool.query(
    'INSERT INTO posts (user_id, title, content, attachments) VALUES ($1, $2, $3, $4) RETURNING *',
    [req.session.userId, title, content, JSON.stringify(attachments || [])]
  );
  res.json(rows[0]);
});

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM posts WHERE id = $1 AND user_id = $2', [req.params.id, req.session.userId]);
  res.json({ ok: true });
});

// Likes
app.post('/api/posts/:id/like', requireAuth, async (req, res) => {
  const postId = req.params.id;
  const userId = req.session.userId;
  const { rows } = await pool.query('SELECT id FROM likes WHERE post_id=$1 AND user_id=$2', [postId, userId]);
  if (rows[0]) {
    await pool.query('DELETE FROM likes WHERE post_id=$1 AND user_id=$2', [postId, userId]);
    res.json({ liked: false });
  } else {
    await pool.query('INSERT INTO likes (post_id, user_id) VALUES ($1, $2)', [postId, userId]);
    res.json({ liked: true });
  }
});

// Comments
app.get('/api/posts/:id/comments', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT c.*, u.username, u.avatar FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.post_id = $1 ORDER BY c.created_at ASC
  `, [req.params.id]);
  res.json(rows);
});

app.post('/api/posts/:id/comments', requireAuth, async (req, res) => {
  const { content, attachments } = req.body;
  if (!content && (!attachments || !attachments.length)) return res.status(400).json({ error: 'Пустой комментарий' });
  const { rows } = await pool.query(
    'INSERT INTO comments (post_id, user_id, content, attachments) VALUES ($1, $2, $3, $4) RETURNING *',
    [req.params.id, req.session.userId, content || '', JSON.stringify(attachments || [])]
  );
  res.json(rows[0]);
});

app.delete('/api/comments/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM comments WHERE id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 http://localhost:${PORT}`));
}).catch(err => { console.error('❌ Ошибка БД:', err.message); process.exit(1); });
