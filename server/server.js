// server/server.js - Complete Payment + Email + Admin System
require('dotenv').config();
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, '..')));

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24, secure: process.env.NODE_ENV === 'production' }
}));

// ---- MySQL Pool ----
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

async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// ---- Email Service ----
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendBillEmail(email, bill) {
  const html = `
    <div style="font-family: Arial; max-width: 600px; margin: 0 auto;">
      <div style="background: #2e2b4f; color: white; padding: 20px; text-align: center;">
        <h1>💼 Innovation Recruitment Services</h1>
        <p>Payment Receipt</p>
      </div>
      <div style="padding: 30px; background: #f9f9f9;">
        <h2>Thank you for your payment!</h2>
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
          <tr style="background: #efefef;">
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Bill #</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">${bill.bill_number}</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Plan</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">${bill.plan_type.toUpperCase()}</td>
          </tr>
          <tr style="background: #efefef;">
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Amount</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">$${parseFloat(bill.amount).toFixed(2)} ${bill.currency}</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Date</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">${new Date(bill.issued_date).toLocaleDateString()}</td>
          </tr>
        </table>
        <p style="color: #666; font-size: 12px;">
          Your account has been upgraded to ${bill.plan_type === 'sme' ? 'SME' : bill.plan_type === 'ent' ? 'Enterprise' : 'Executive'} Recruitment Plan.
          <br/>You can now post jobs and manage candidates.
        </p>
      </div>
      <div style="background: #2e2b4f; color: white; padding: 20px; text-align: center; font-size: 12px;">
        <p>Questions? Contact: <strong>rm@innovation-rs.com</strong></p>
        <p>© 2025 Innovation RS. All rights reserved.</p>
      </div>
    </div>
  `;
  
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: `Payment Confirmed - Bill #${bill.bill_number}`,
    html
  });
}

// ---- Auth Helpers ----
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'not logged in' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') 
    return res.status(403).json({ error: 'admin only' });
  next();
}

// ---- Auth Routes ----
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'missing fields' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await query('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, hash]);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'email exists' });
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'missing' });
  try {
    const rows = await query('SELECT id, name, email, password_hash, role FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(400).json({ error: 'invalid' });
    const u = rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(400).json({ error: 'invalid' });
    req.session.user = { id: u.id, name: u.name, email: u.email, role: u.role };
    res.json({ ok: true, user: req.session.user });
  } catch (e) {
    res.status(500).json({ error: 'server' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// ---- PayPal Integration ----
const PAYPAL_BASE = process.env.PAYPAL_MODE === 'live' 
  ? 'https://api-m.paypal.com' 
  : 'https://api-m.sandbox.paypal.com';

async function paypalRequest(pathSuffix, method = 'POST', body = null) {
  const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64');
  const resp = await fetch(PAYPAL_BASE + pathSuffix, {
    method,
    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await resp.json();
  return { status: resp.status, data };
}

// ---- Payment Endpoints ----

// Generate custom payment link (admin only)
app.post('/api/generate-payment-link', requireAdmin, async (req, res) => {
  const { amount, client_email, description } = req.body;
  if (!amount || !client_email) return res.status(400).json({ error: 'missing' });
  try {
    const token = crypto.randomBytes(32).toString('hex');
    const result = await query(
      'INSERT INTO payments (amount, client_email, custom_link_token, plan_type, notes) VALUES (?, ?, ?, ?, ?)',
      [amount, client_email, token, 'custom', description || '']
    );
    const link = `${process.env.BASE_URL || 'http://localhost:3000'}/payment-entry.html?token=${token}`;
    res.json({ ok: true, link, paymentId: result.insertId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server' });
  }
});

// Get payment details by token
app.get('/api/payment-link/:token', async (req, res) => {
  try {
    const rows = await query('SELECT id, amount, client_email, plan_type FROM payments WHERE custom_link_token = ?', [req.params.token]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'server' });
  }
});

// Create PayPal order
app.post('/api/create-paypal-order', async (req, res) => {
  const { amount, plan } = req.body;
  if (!amount) return res.status(400).json({ error: 'missing amount' });
  try {
    const { status, data } = await paypalRequest('/v2/checkout/orders', 'POST', {
      intent: 'CAPTURE',
      purchase_units: [{
        amount: { currency_code: process.env.PAYPAL_CURRENCY || 'USD', value: amount }
      }]
    });
    if (status >= 400) return res.status(500).json({ error: 'paypal failed' });
    
    // Record pending payment
    await query(
      'INSERT INTO payments (paypal_order_id, amount, plan_type, status, user_id) VALUES (?, ?, ?, ?, ?)',
      [data.id, amount, plan || 'custom', 'pending', req.session.user?.id || null]
    );
    
    res.json({ orderID: data.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'paypal error' });
  }
});

// Capture PayPal order & generate bill
app.post('/api/capture-paypal-order', async (req, res) => {
  const { orderID, plan } = req.body;
  if (!orderID) return res.status(400).json({ error: 'missing orderID' });
  try {
    const { status, data } = await paypalRequest(`/v2/checkout/orders/${orderID}/capture`, 'POST');
    if (status >= 400) return res.status(500).json({ error: 'capture failed' });

    // Get order amount
    const amount = data.purchase_units[0].amount.value;
    
    // Update payment record
    await query('UPDATE payments SET status = ? WHERE paypal_order_id = ?', ['completed', orderID]);

    // Upgrade user to poster if logged in
    let userEmail = null;
    if (req.session.user) {
      await query('UPDATE users SET role = ? WHERE id = ?', ['poster', req.session.user.id]);
      req.session.user.role = 'poster';
      userEmail = req.session.user.email;
    }

    // Create bill
    const billNumber = `INV-${Date.now()}`;
    const paymentRows = await query('SELECT id FROM payments WHERE paypal_order_id = ?', [orderID]);
    const paymentId = paymentRows[0].id;

    await query(
      'INSERT INTO bills (payment_id, bill_number, user_id, amount, plan_type, currency, client_email) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [paymentId, billNumber, req.session.user?.id || null, amount, plan || 'custom', 'USD', userEmail]
    );

    // Send email
    if (userEmail) {
      const billData = { bill_number: billNumber, amount, plan_type: plan || 'custom', issued_date: new Date(), currency: 'USD' };
      await sendBillEmail(userEmail, billData);
      
      // Mark as sent
      await query('UPDATE bills SET sent_via_email = 1 WHERE bill_number = ?', [billNumber]);
    }

    res.json({ ok: true, orderID, message: 'Payment received. Bill sent via email.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'capture error' });
  }
});

// ---- Admin Endpoints ----

// Get all payments
app.get('/api/admin/payments', requireAdmin, async (req, res) => {
  try {
    const { period = 'all' } = req.query;
    let whereClause = '';
    if (period === 'today') whereClause = ' WHERE DATE(created_at) = CURDATE()';
    else if (period === 'month') whereClause = ' WHERE MONTH(created_at) = MONTH(NOW()) AND YEAR(created_at) = YEAR(NOW())';

    const payments = await query(`
      SELECT p.*, b.bill_number FROM payments p
      LEFT JOIN bills b ON b.payment_id = p.id
      ${whereClause}
      ORDER BY p.created_at DESC
    `);
    
    const total = payments.reduce((sum, p) => sum + parseFloat(p.amount), 0);
    res.json({ payments, total, count: payments.length });
  } catch (e) {
    res.status(500).json({ error: 'server' });
  }
});

// Health check
app.get('/health', (req, res) => res.json({ ok: true }));

// ---- Start Server ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📧 Email: ${process.env.SMTP_USER}`);
  console.log(`💳 PayPal Mode: ${process.env.PAYPAL_MODE || 'sandbox'}`);
});
