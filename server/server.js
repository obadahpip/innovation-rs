// server/server.js
// Full server file for Innovation-RS job board
// Node 18+ recommended. If Node <18 install node-fetch (npm i node-fetch).
// Required env vars (put in server/.env):
// DB_HOST, DB_USER, DB_PASS, DB_NAME, SESSION_SECRET,
// PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_CURRENCY (optional)

require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const cors = require('cors');

// fetch fallback for Node < 18
let fetchFunc = global.fetch;
if (!fetchFunc) {
  try {
    fetchFunc = (...args) => require('node-fetch')(...args);
  } catch (e) {
    console.error('node-fetch not installed and global.fetch missing. Install node-fetch for Node < 18.');
    throw e;
  }
}

// ---- Config & app init ----
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Serve static frontend (project root)
// Assumes project root structure: server/ (this file) and frontend files in parent dir
app.use(express.static(path.join(__dirname, '..')));

// Session (MemoryStore OK for dev; replace in production)
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET not set. Use a strong secret in production.');
}
app.use(session({
  secret: process.env.SESSION_SECRET || 'devsecret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// ---- MySQL pool ----
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'innovation_rs_jobs',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
});

// simple query helper
async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// ---- Upload (Multer) ----
const iconDir = path.join(__dirname, '..', 'assets', 'photos', 'jobs');
if (!fs.existsSync(iconDir)) fs.mkdirSync(iconDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, iconDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2,8) + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB default - change as needed
  fileFilter: (req, file, cb) => {
    // allow common image types
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Only images allowed'));
    cb(null, true);
  }
});

// ---- Auth helpers ----
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'not logged in' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}
function requirePosterOrAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'not logged in' });
  if (req.session.user.role !== 'poster' && req.session.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}

// ---- Routes: Auth ----
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await query('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, hash]);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'email exists' });
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'missing' });
  try {
    const rows = await query('SELECT id,name,email,password_hash,role FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(400).json({ error: 'invalid' });
    const u = rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(400).json({ error: 'invalid' });
    req.session.user = { id: u.id, name: u.name, email: u.email, role: u.role };
    res.json({ ok: true, user: req.session.user });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// ---- PayPal helper & endpoints (sandbox by default) ----
const PAYPAL_BASE = process.env.PAYPAL_MODE === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
async function paypalRequest(pathSuffix, method='POST', body=null) {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const secret = process.env.PAYPAL_CLIENT_SECRET;
  if (!clientId || !secret) throw new Error('PayPal credentials not set');
  const auth = Buffer.from(`${clientId}:${secret}`).toString('base64');
  const headers = { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' };
  const url = PAYPAL_BASE + pathSuffix;
  const resp = await fetchFunc(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await resp.json();
  return { status: resp.status, data };
}

app.post('/api/create-paypal-order', requireLogin, async (req, res) => {
  const price = req.body.price || '10.00';
  const currency = process.env.PAYPAL_CURRENCY || 'USD';
  const payload = {
    intent: 'CAPTURE',
    purchase_units: [{ amount: { currency_code: currency, value: price } }]
  };
  try {
    const { status, data } = await paypalRequest('/v2/checkout/orders', 'POST', payload);
    if (status >= 400) return res.status(500).json({ error: 'paypal create failed', data });
    res.json({ orderID: data.id });
  } catch (e) {
    console.error('paypal create error', e);
    res.status(500).json({ error: 'paypal error' });
  }
});

app.post('/api/capture-paypal-order', requireLogin, async (req, res) => {
  const { orderID } = req.body;
  if (!orderID) return res.status(400).json({ error: 'missing orderID' });
  try {
    const { status, data } = await paypalRequest(`/v2/checkout/orders/${orderID}/capture`, 'POST', null);
    if (status >= 400) return res.status(500).json({ error: 'capture failed', data });
    // On successful capture, upgrade user to poster
    await query('UPDATE users SET role = ? WHERE id = ?', ['poster', req.session.user.id]);
    req.session.user.role = 'poster';
    res.json({ ok: true, data });
  } catch (e) {
    console.error('paypal capture error', e);
    res.status(500).json({ error: 'paypal capture failed' });
  }
});

// ---- Jobs CRUD & Search ----

// Create job - poster only
app.post('/api/jobs', requireLogin, requirePosterOrAdmin, upload.single('icon'), async (req, res) => {
  try {
    const { title, description, tags, apply_link } = req.body;
    if (!title) return res.status(400).json({ error: 'title required' });
    const icon = req.file ? path.join('assets','photos','jobs', path.basename(req.file.path)) : null;
    const [result] = await pool.execute(
      'INSERT INTO jobs (poster_id, icon, title, description, apply_link, approved) VALUES (?, ?, ?, ?, ?, ?)',
      [req.session.user.id, icon, title, description || '', apply_link || '', 0]
    );
    const jobId = result.insertId;
    if (tags && tags.trim()) {
      const tagList = tags.split(',').map(t => t.trim().toLowerCase()).filter(Boolean);
      for (const t of tagList) {
        const existing = await query('SELECT id FROM tags WHERE name = ?', [t]);
        let tagId;
        if (existing.length) tagId = existing[0].id;
        else {
          const ins = await query('INSERT INTO tags (name) VALUES (?)', [t]);
          // mysql2 returns result object, but our helper returns rows - use pool.execute above for insert if you want insertId
          const [rr] = await pool.execute('SELECT id FROM tags WHERE name = ?', [t]);
          tagId = rr[0].id;
        }
        await query('INSERT IGNORE INTO job_tags (job_id, tag_id) VALUES (?, ?)', [jobId, tagId]);
      }
    }
    res.json({ ok: true, jobId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// Edit job (owner or admin)
app.put('/api/jobs/:id', requireLogin, upload.single('icon'), async (req, res) => {
  try {
    const jobId = Number(req.params.id);
    const rows = await query('SELECT poster_id FROM jobs WHERE id = ?', [jobId]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    const posterId = rows[0].poster_id;
    if (posterId !== req.session.user.id && req.session.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });

    const { title, description, tags, apply_link } = req.body;
    const icon = req.file ? path.join('assets','photos','jobs', path.basename(req.file.path)) : null;
    const sets = [];
    const params = [];
    if (title) { sets.push('title = ?'); params.push(title); }
    if (description) { sets.push('description = ?'); params.push(description); }
    if (apply_link !== undefined) { sets.push('apply_link = ?'); params.push(apply_link); }
    if (icon) { sets.push('icon = ?'); params.push(icon); }
    if (sets.length) {
      params.push(jobId);
      await query(`UPDATE jobs SET ${sets.join(', ')} WHERE id = ?`, params);
    }
    if (tags !== undefined) {
      await query('DELETE FROM job_tags WHERE job_id = ?', [jobId]);
      const tagList = tags.split(',').map(t => t.trim().toLowerCase()).filter(Boolean);
      for (const t of tagList) {
        const existing = await query('SELECT id FROM tags WHERE name = ?', [t]);
        let tagId;
        if (existing.length) tagId = existing[0].id;
        else {
          const ins = await pool.execute('INSERT INTO tags (name) VALUES (?)', [t]);
          tagId = ins[0].insertId;
        }
        await query('INSERT IGNORE INTO job_tags (job_id, tag_id) VALUES (?, ?)', [jobId, tagId]);
      }
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// Delete job (owner or admin)
app.delete('/api/jobs/:id', requireLogin, async (req, res) => {
  try {
    const jobId = Number(req.params.id);
    const rows = await query('SELECT poster_id FROM jobs WHERE id = ?', [jobId]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    const posterId = rows[0].poster_id;
    if (posterId !== req.session.user.id && req.session.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    await query('DELETE FROM jobs WHERE id = ?', [jobId]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server error' });
  }
});

// Approve job (admin)
app.post('/api/jobs/:id/approve', requireAdmin, async (req, res) => {
  try {
    const jobId = Number(req.params.id);
    await query('UPDATE jobs SET approved = 1 WHERE id = ?', [jobId]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'db error' });
  }
});

// Search & list endpoint
app.get('/api/jobs', async (req, res) => {
  try {
    let { q, time, tag, onlyApproved } = req.query;
    onlyApproved = (onlyApproved === '0' || onlyApproved === 'false') ? 0 : 1;

    if (q && q.trim().toLowerCase().startsWith('tag:')) {
      tag = q.trim().slice(4).trim();
      q = '';
    }

    const params = [];
    let where = 'WHERE 1=1';
    if (onlyApproved) where += ' AND j.approved = 1';
    if (q && q.trim()) {
      where += ' AND (j.title LIKE ? OR j.description LIKE ?)';
      const like = '%' + q.trim() + '%';
      params.push(like, like);
    }
    if (tag && tag.trim()) {
      where += ' AND t.name = ?';
      params.push(tag.trim().toLowerCase());
    }
    if (time && time !== 'all') {
      if (time === '24h') where += ' AND j.post_time >= (NOW() - INTERVAL 1 DAY)';
      else if (time === '7d') where += ' AND j.post_time >= (NOW() - INTERVAL 7 DAY)';
      else if (time === '30d') where += ' AND j.post_time >= (NOW() - INTERVAL 30 DAY)';
    }

    const sql = `
      SELECT j.*, u.name AS poster_name, GROUP_CONCAT(t.name) AS tags
      FROM jobs j
      LEFT JOIN users u ON u.id = j.poster_id
      LEFT JOIN job_tags jt ON jt.job_id = j.id
      LEFT JOIN tags t ON t.id = jt.tag_id
      ${where}
      GROUP BY j.id
      ORDER BY j.post_time DESC
      LIMIT 500
    `;
    const rows = await query(sql, params);
    res.json({ jobs: rows });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server error' });
  }
});

// Admin-only job list for management UI
app.get('/api/admin/jobs', requireAdmin, async (req, res) => {
  try {
    const rows = await query(`
      SELECT j.*, u.name AS poster_name, GROUP_CONCAT(t.name) AS tags
      FROM jobs j
      LEFT JOIN users u ON u.id = j.poster_id
      LEFT JOIN job_tags jt ON jt.job_id = j.id
      LEFT JOIN tags t ON t.id = jt.tag_id
      GROUP BY j.id
      ORDER BY j.post_time DESC
    `);
    res.json({ jobs: rows });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'db' });
  }
});

// ---- Simple health route ----
app.get('/health', (req, res) => res.json({ ok: true }));

// ---- Start server ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
