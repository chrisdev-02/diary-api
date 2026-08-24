const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const logApiError = (route, err, req) => {
  console.error(`[API ERROR] ${req.method} ${route}`, {
    message: err.message,
    code: err.code,
    detail: err.detail,
    stack: err.stack,
  });
};

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expects: "Bearer <TOKEN>"

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// --- AUTH ROUTES ---

// 1. User Registration
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    logApiError('/api/auth/register', err, req);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// 2. User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = userRes.rows[0];

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (err) {
    logApiError('/api/auth/login', err, req);
    res.status(500).json({ error: err.message });
  }
});

// --- RECORDS ROUTES (Protected) ---

// 3. Create Record (Accepts dynamic metadata JSON)
app.post('/api/records', authenticateToken, async (req, res) => {
  const { record_type, metadata } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO records (user_id, record_type, metadata) VALUES ($1, $2, $3) RETURNING *',
      [req.user.userId, record_type, metadata || {}]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logApiError('/api/records POST', err, req);
    res.status(500).json({ error: err.message });
  }
});

// 4. Get User Records (Supports optional type filtering: /api/records?type=diary)
app.get('/api/records', authenticateToken, async (req, res) => {
  const { type } = req.query;

  try {
    let query = 'SELECT * FROM records WHERE user_id = $1';
    let params = [req.user.userId];

    if (type) {
      query += ' AND record_type = $2';
      params.push(type);
    }

    query += ' ORDER BY created_at DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    logApiError('/api/records GET', err, req);
    res.status(500).json({ error: err.message });
  }
});

// 5. Delete Record
app.delete('/api/records/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'DELETE FROM records WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, req.user.userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Record not found or unauthorized' });
    }

    res.json({ message: 'Record deleted successfully' });
  } catch (err) {
    logApiError('/api/records DELETE', err, req);
    res.status(500).json({ error: err.message });
  }
});

app.use((err, req, res, next) => {
  logApiError('unhandled request', err, req);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));