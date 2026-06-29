const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const multer = require('multer');

// fetch is built-in since Node 18; polyfill for older versions
const fetch = globalThis.fetch || require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Multer — храним файлы в памяти, потом пишем в БД
const ALLOWED_MIME = new Set([
  'image/gif','image/png','image/jpeg','image/webp',
  'video/mp4',
  'audio/ogg','audio/mpeg','audio/mp3',
]);
const AVATAR_MIME = new Set(['image/gif','image/png','image/jpeg','image/webp']);

const memStorage = multer.memoryStorage();

const upload = multer({
  storage: memStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME.has(file.mimetype)) cb(null, true);
    else cb(new Error('Недопустимый тип файла'));
  },
});

const avatarUpload = multer({
  storage: memStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (AVATAR_MIME.has(file.mimetype)) cb(null, true);
    else cb(new Error('Только изображения для аватара'));
  },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      bio TEXT DEFAULT '',
      avatar_data BYTEA,
      avatar_mime TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_data BYTEA;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_mime TEXT;

    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      content TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS post_files (
      id SERIAL PRIMARY KEY,
      post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      name TEXT,
      mime TEXT,
      data BYTEA,
      size INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );

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
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS comment_files (
      id SERIAL PRIMARY KEY,
      comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
      name TEXT,
      mime TEXT,
      data BYTEA,
      size INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      actor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tracks (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      artist TEXT NOT NULL,
      audio_data BYTEA NOT NULL,
      audio_mime TEXT NOT NULL,
      audio_size INTEGER,
      cover_data BYTEA,
      cover_mime TEXT,
      duration INTEGER,
      plays INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS track_likes (
      id SERIAL PRIMARY KEY,
      track_id INTEGER REFERENCES tracks(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(track_id, user_id)
    );
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

const ADMIN_USERNAME = 'FokzBurmalda';

async function isAdmin(userId) {
  const { rows } = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
  return rows[0] && rows[0].username === ADMIN_USERNAME;
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}

app.get('/api/status', (req, res) => res.json({ ok: true, uptime: process.uptime() }));

// ── AUTH ─────────────────────────────────────────────
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
  const { rows } = await pool.query(
    'SELECT id, username, bio, (avatar_data IS NOT NULL) AS has_avatar, created_at FROM users WHERE id = $1',
    [req.session.userId]
  );
  const u = rows[0];
  res.json({ ...u, avatar: u.has_avatar ? `/api/avatar/${u.id}` : '' });
});

// ── AVATAR SERVE ─────────────────────────────────────
app.get('/api/avatar/:id', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT avatar_data, avatar_mime FROM users WHERE id = $1',
    [req.params.id]
  );
  if (!rows[0] || !rows[0].avatar_data) return res.status(404).end();
  res.set('Content-Type', rows[0].avatar_mime);
  res.set('Cache-Control', 'no-cache');
  res.send(rows[0].avatar_data);
});

// ── FILE SERVE ───────────────────────────────────────
app.get('/api/file/:id', async (req, res) => {
  // Check post_files first, then comment_files
  let result = await pool.query('SELECT name, mime, data FROM post_files WHERE id = $1', [req.params.id]);
  if (!result.rows[0]) {
    result = await pool.query('SELECT name, mime, data FROM comment_files WHERE id = $1', [req.params.id]);
  }
  if (!result.rows[0]) return res.status(404).end();
  const { name, mime, data } = result.rows[0];
  res.set('Content-Type', mime);
  res.set('Content-Disposition', `inline; filename="${encodeURIComponent(name)}"`);
  res.set('Cache-Control', 'public, max-age=31536000');
  res.send(data);
});

// ── UPLOAD ───────────────────────────────────────────
app.post('/api/upload', requireAuth, upload.array('files', 10), async (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'Нет файлов' });
  // We store them temporarily and return IDs — actual DB insert happens when post/comment is created
  // Instead: store now as orphan rows in post_files with post_id=NULL, then link on post creation
  const files = [];
  for (const f of req.files) {
    const { rows } = await pool.query(
      'INSERT INTO post_files (name, mime, data, size) VALUES ($1, $2, $3, $4) RETURNING id',
      [f.originalname, f.mimetype, f.buffer, f.size]
    );
    files.push({
      id: rows[0].id,
      url: `/api/file/${rows[0].id}`,
      name: f.originalname,
      mime: f.mimetype,
      size: f.size,
    });
  }
  res.json({ files });
});

// ── PROFILE ──────────────────────────────────────────
app.get('/api/profile/:id', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, bio, (avatar_data IS NOT NULL) AS has_avatar, created_at FROM users WHERE id = $1',
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
  const u = rows[0];
  res.json({ ...u, avatar: u.has_avatar ? `/api/avatar/${u.id}` : '' });
});

app.post('/api/profile/bio', requireAuth, async (req, res) => {
  const { bio } = req.body;
  await pool.query('UPDATE users SET bio = $1 WHERE id = $2', [bio || '', req.session.userId]);
  res.json({ ok: true });
});

app.post('/api/profile/avatar', requireAuth, avatarUpload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
  await pool.query(
    'UPDATE users SET avatar_data = $1, avatar_mime = $2 WHERE id = $3',
    [req.file.buffer, req.file.mimetype, req.session.userId]
  );
  res.json({ url: `/api/avatar/${req.session.userId}` });
});

// ── POSTS ────────────────────────────────────────────
app.get('/api/posts', async (req, res) => {
  const userId = req.session.userId || 0;
  const { rows } = await pool.query(`
    SELECT p.id, p.user_id, p.title, p.content, p.created_at,
      u.username, (u.avatar_data IS NOT NULL) AS has_avatar,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes_count,
      (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comments_count,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_id = $1) AS user_liked
    FROM posts p JOIN users u ON p.user_id = u.id
    ORDER BY p.created_at DESC
  `, [userId]);

  // Attach file metadata for each post
  const postIds = rows.map(r => r.id);
  let fileRows = [];
  if (postIds.length) {
    const fr = await pool.query(
      'SELECT id, post_id, name, mime, size FROM post_files WHERE post_id = ANY($1)',
      [postIds]
    );
    fileRows = fr.rows;
  }

  const result = rows.map(p => ({
    ...p,
    avatar: p.has_avatar ? `/api/avatar/${p.user_id}` : '',
    attachments: fileRows
      .filter(f => f.post_id === p.id)
      .map(f => ({ id: f.id, url: `/api/file/${f.id}`, name: f.name, mime: f.mime, size: f.size })),
  }));
  res.json(result);
});

app.post('/api/posts', requireAuth, async (req, res) => {
  const { title, content, attachments } = req.body;
  if (!title) return res.status(400).json({ error: 'Нужен заголовок' });
  const { rows } = await pool.query(
    'INSERT INTO posts (user_id, title, content) VALUES ($1, $2, $3) RETURNING *',
    [req.session.userId, title, content]
  );
  const postId = rows[0].id;
  // Link uploaded files to this post
  if (attachments && attachments.length) {
    const ids = attachments.map(a => a.id).filter(Boolean);
    if (ids.length) {
      await pool.query('UPDATE post_files SET post_id = $1 WHERE id = ANY($2)', [postId, ids]);
    }
  }
  res.json(rows[0]);
});

// ── EDIT POST (owner or admin) ───────────────────────
app.put('/api/posts/:id', requireAuth, async (req, res) => {
  const { title, content, addAttachments, removeFileIds } = req.body;
  const userId = req.session.userId;
  const admin = await isAdmin(userId);
  const { rows } = await pool.query('SELECT user_id FROM posts WHERE id = $1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Пост не найден' });
  if (!admin && rows[0].user_id !== userId) return res.status(403).json({ error: 'Нет доступа' });

  if (title !== undefined || content !== undefined) {
    await pool.query(
      'UPDATE posts SET title = COALESCE($1, title), content = COALESCE($2, content) WHERE id = $3',
      [title || null, content !== undefined ? content : null, req.params.id]
    );
  }
  // Remove selected files
  if (removeFileIds && removeFileIds.length) {
    await pool.query('DELETE FROM post_files WHERE id = ANY($1) AND post_id = $2', [removeFileIds, req.params.id]);
  }
  // Link new uploaded files
  if (addAttachments && addAttachments.length) {
    const ids = addAttachments.map(a => a.id).filter(Boolean);
    if (ids.length) await pool.query('UPDATE post_files SET post_id = $1 WHERE id = ANY($2)', [req.params.id, ids]);
  }
  res.json({ ok: true });
});

// ── DELETE POST (owner or admin) ─────────────────────
app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const admin = await isAdmin(userId);
  if (admin) {
    await pool.query('DELETE FROM posts WHERE id = $1', [req.params.id]);
  } else {
    await pool.query('DELETE FROM posts WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
  }
  res.json({ ok: true });
});

// ── LIKES ────────────────────────────────────────────
app.post('/api/posts/:id/like', requireAuth, async (req, res) => {
  const postId = req.params.id;
  const userId = req.session.userId;
  const { rows } = await pool.query('SELECT id FROM likes WHERE post_id=$1 AND user_id=$2', [postId, userId]);
  if (rows[0]) {
    await pool.query('DELETE FROM likes WHERE post_id=$1 AND user_id=$2', [postId, userId]);
    res.json({ liked: false });
  } else {
    await pool.query('INSERT INTO likes (post_id, user_id) VALUES ($1, $2)', [postId, userId]);
    // Notify post owner (not self)
    const postOwner = await pool.query('SELECT user_id FROM posts WHERE id=$1', [postId]);
    if (postOwner.rows[0] && postOwner.rows[0].user_id !== userId) {
      await pool.query(
        'INSERT INTO notifications (user_id, actor_id, type, post_id) VALUES ($1, $2, $3, $4)',
        [postOwner.rows[0].user_id, userId, 'like', postId]
      );
    }
    res.json({ liked: true });
  }
});

// ── COMMENTS ─────────────────────────────────────────
app.get('/api/posts/:id/comments', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT c.id, c.post_id, c.user_id, c.content, c.created_at,
      u.username, (u.avatar_data IS NOT NULL) AS has_avatar
    FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.post_id = $1 ORDER BY c.created_at ASC
  `, [req.params.id]);

  const commentIds = rows.map(r => r.id);
  let fileRows = [];
  if (commentIds.length) {
    const fr = await pool.query(
      'SELECT id, comment_id, name, mime, size FROM comment_files WHERE comment_id = ANY($1)',
      [commentIds]
    );
    fileRows = fr.rows;
  }

  const result = rows.map(c => ({
    ...c,
    avatar: c.has_avatar ? `/api/avatar/${c.user_id}` : '',
    attachments: fileRows
      .filter(f => f.comment_id === c.id)
      .map(f => ({ id: f.id, url: `/api/file/${f.id}`, name: f.name, mime: f.mime, size: f.size })),
  }));
  res.json(result);
});

app.post('/api/posts/:id/comments', requireAuth, async (req, res) => {
  const { content, attachments } = req.body;
  if (!content && (!attachments || !attachments.length)) return res.status(400).json({ error: 'Пустой комментарий' });
  const { rows } = await pool.query(
    'INSERT INTO comments (post_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
    [req.params.id, req.session.userId, content || '']
  );
  const commentId = rows[0].id;
  // Move uploaded files from post_files to comment_files
  if (attachments && attachments.length) {
    for (const a of attachments) {
      if (!a.id) continue;
      const pf = await pool.query('SELECT * FROM post_files WHERE id = $1', [a.id]);
      if (pf.rows[0]) {
        await pool.query(
          'INSERT INTO comment_files (comment_id, name, mime, data, size) VALUES ($1, $2, $3, $4, $5)',
          [commentId, pf.rows[0].name, pf.rows[0].mime, pf.rows[0].data, pf.rows[0].size]
        );
        await pool.query('DELETE FROM post_files WHERE id = $1', [a.id]);
      }
    }
  }
  // Notify post owner (not self)
  const postOwner = await pool.query('SELECT user_id FROM posts WHERE id=$1', [req.params.id]);
  if (postOwner.rows[0] && postOwner.rows[0].user_id !== req.session.userId) {
    await pool.query(
      'INSERT INTO notifications (user_id, actor_id, type, post_id, comment_id) VALUES ($1, $2, $3, $4, $5)',
      [postOwner.rows[0].user_id, req.session.userId, 'comment', req.params.id, commentId]
    );
  }
  res.json(rows[0]);
});

app.delete('/api/comments/:id', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const admin = await isAdmin(userId);
  if (admin) {
    await pool.query('DELETE FROM comments WHERE id=$1', [req.params.id]);
  } else {
    await pool.query('DELETE FROM comments WHERE id=$1 AND user_id=$2', [req.params.id, userId]);
  }
  res.json({ ok: true });
});

// ── DELETE FILE FROM POST (admin only) ───────────────
app.delete('/api/file/:id', requireAuth, async (req, res) => {
  const admin = await isAdmin(req.session.userId);
  if (!admin) return res.status(403).json({ error: 'Нет доступа' });
  await pool.query('DELETE FROM post_files WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ── ADMIN CHECK ──────────────────────────────────────
app.get('/api/is-admin', requireAuth, async (req, res) => {
  res.json({ admin: await isAdmin(req.session.userId) });
});

// ── NOTIFICATIONS ────────────────────────────────────
app.get('/api/notifications', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT n.id, n.type, n.is_read, n.created_at, n.post_id, n.comment_id,
      u.username AS actor_username, (u.avatar_data IS NOT NULL) AS actor_has_avatar, u.id AS actor_id,
      p.title AS post_title
    FROM notifications n
    JOIN users u ON n.actor_id = u.id
    LEFT JOIN posts p ON n.post_id = p.id
    WHERE n.user_id = $1
    ORDER BY n.created_at DESC
    LIMIT 50
  `, [req.session.userId]);
  res.json(rows.map(r => ({
    ...r,
    actor_avatar: r.actor_has_avatar ? `/api/avatar/${r.actor_id}` : ''
  })));
});

app.get('/api/notifications/unread-count', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT COUNT(*) AS count FROM notifications WHERE user_id=$1 AND is_read=FALSE',
    [req.session.userId]
  );
  res.json({ count: parseInt(rows[0].count) });
});

app.post('/api/notifications/read-all', requireAuth, async (req, res) => {
  await pool.query('UPDATE notifications SET is_read=TRUE WHERE user_id=$1', [req.session.userId]);
  res.json({ ok: true });
});

app.post('/api/notifications/:id/read', requireAuth, async (req, res) => {
  await pool.query('UPDATE notifications SET is_read=TRUE WHERE id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
  res.json({ ok: true });
});

// ── MUSIC ────────────────────────────────────────────
const AUDIO_MIME = new Set(['audio/mpeg','audio/mp3','audio/ogg','audio/wav','audio/flac','audio/aac','audio/x-m4a']);
const COVER_MIME = new Set(['image/jpeg','image/png','image/webp','image/gif']);

const trackAudioUpload = multer({
  storage: memStorage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'audio' && AUDIO_MIME.has(file.mimetype)) cb(null, true);
    else if (file.fieldname === 'cover' && COVER_MIME.has(file.mimetype)) cb(null, true);
    else cb(new Error('Недопустимый тип файла'));
  },
}).fields([{ name:'audio', maxCount:1 }, { name:'cover', maxCount:1 }]);

app.get('/api/tracks', async (req, res) => {
  const userId = req.session.userId || 0;
  const { rows } = await pool.query(`
    SELECT t.id, t.title, t.artist, t.audio_mime, t.audio_size, t.plays, t.created_at,
      (t.cover_data IS NOT NULL) AS has_cover,
      u.username, u.id AS user_id,
      (SELECT COUNT(*) FROM track_likes WHERE track_id = t.id) AS likes_count,
      (SELECT COUNT(*) FROM track_likes WHERE track_id = t.id AND user_id = $1) AS user_liked
    FROM tracks t JOIN users u ON t.user_id = u.id
    ORDER BY t.created_at DESC
  `, [userId]);
  res.json(rows.map(r => ({ ...r, cover: r.has_cover ? `/api/tracks/${r.id}/cover` : null })));
});

app.post('/api/tracks', requireAuth, (req, res) => {
  trackAudioUpload(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    const audioFile = req.files && req.files.audio && req.files.audio[0];
    const coverFile = req.files && req.files.cover && req.files.cover[0];
    if (!audioFile) return res.status(400).json({ error: 'Аудиофайл обязателен' });
    const { title, artist } = req.body;
    if (!title || !artist) return res.status(400).json({ error: 'Укажите название и исполнителя' });
    const { rows } = await pool.query(
      `INSERT INTO tracks (user_id, title, artist, audio_data, audio_mime, audio_size, cover_data, cover_mime)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [req.session.userId, title, artist,
       audioFile.buffer, audioFile.mimetype, audioFile.size,
       coverFile ? coverFile.buffer : null,
       coverFile ? coverFile.mimetype : null]
    );
    res.json({ id: rows[0].id });
  });
});

app.get('/api/tracks/:id/audio', async (req, res) => {
  const { rows } = await pool.query('SELECT audio_data, audio_mime FROM tracks WHERE id=$1', [req.params.id]);
  if (!rows[0]) return res.status(404).end();
  await pool.query('UPDATE tracks SET plays = plays + 1 WHERE id=$1', [req.params.id]);
  res.set('Content-Type', rows[0].audio_mime);
  res.set('Accept-Ranges', 'bytes');
  res.set('Cache-Control', 'public, max-age=86400');
  res.send(rows[0].audio_data);
});

app.get('/api/tracks/:id/cover', async (req, res) => {
  const { rows } = await pool.query('SELECT cover_data, cover_mime FROM tracks WHERE id=$1', [req.params.id]);
  if (!rows[0] || !rows[0].cover_data) return res.status(404).end();
  res.set('Content-Type', rows[0].cover_mime);
  res.set('Cache-Control', 'public, max-age=86400');
  res.send(rows[0].cover_data);
});

app.post('/api/tracks/:id/like', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT id FROM track_likes WHERE track_id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
  if (rows[0]) {
    await pool.query('DELETE FROM track_likes WHERE track_id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
    res.json({ liked: false });
  } else {
    await pool.query('INSERT INTO track_likes (track_id, user_id) VALUES ($1,$2)', [req.params.id, req.session.userId]);
    res.json({ liked: true });
  }
});

app.delete('/api/tracks/:id', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const admin = await isAdmin(userId);
  if (admin) {
    await pool.query('DELETE FROM tracks WHERE id=$1', [req.params.id]);
  } else {
    await pool.query('DELETE FROM tracks WHERE id=$1 AND user_id=$2', [req.params.id, userId]);
  }
  res.json({ ok: true });
});

// ── AI PROXY (Ollama via tunnel) ─────────────────────
const OLLAMA_TUNNEL = process.env.OLLAMA_TUNNEL || 'http://bore.pub:46148';

app.post('/api/ai/chat', async (req, res) => {
  try {
    const ollamaRes = await fetch(`${OLLAMA_TUNNEL}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });

    if (!ollamaRes.ok) {
      const text = await ollamaRes.text();
      return res.status(ollamaRes.status).json({ error: text });
    }

    res.setHeader('Content-Type', 'application/x-ndjson');
    res.setHeader('Transfer-Encoding', 'chunked');
    ollamaRes.body.pipe(res);
  } catch (e) {
    res.status(500).json({ error: 'Ollama недоступен: ' + e.message });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 http://localhost:${PORT}`));
}).catch(err => { console.error('❌ Ошибка БД:', err.message); process.exit(1); });
