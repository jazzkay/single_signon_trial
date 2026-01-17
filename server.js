require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const cors = require('cors');

// Initialize Express
const app = express();
// Log all incoming requests
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.originalUrl}`);
  next();
});


// ======================
// Configuration
// ======================
const PORT = process.env.PORT || 3000;
const JWT_CONFIG = {
  secret: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  expiresIn: process.env.JWT_EXPIRES || '1h'
};

// ======================
// Middleware
// ======================
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:8000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => {
    res.set('Cache-Control', 'public, max-age=3600');
  }
}));

// ======================
// Database Setup
// ======================
const db = new sqlite3.Database(
  './sso.db',
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) {
      console.error('Database connection error:', err.message);
      process.exit(1);
    }
    console.log('Connected to SQLite database');
  }
);

const initializeDatabase = () => {
  const queries = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS auth_codes (
      code TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`,
    `CREATE TABLE IF NOT EXISTS clients (
      client_id TEXT PRIMARY KEY,
      client_secret TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      name TEXT
    )`
  ];

  return Promise.all(
    queries.map(
      (query) => new Promise((resolve, reject) => {
        db.run(query, (err) => {
          if (err) reject(err);
          else resolve();
        });
      })
    )
  );
};

const seedDemoClient = () => {
  return new Promise((resolve, reject) => {
    db.get("SELECT COUNT(*) as count FROM clients", (err, row) => {
      if (err) return reject(err);
      if (row.count === 0) {
        db.run(
          `INSERT INTO clients (client_id, client_secret, redirect_uri, name)
           VALUES (?, ?, ?, ?)`,
          [
            'demo-client',
            crypto.randomBytes(16).toString('hex'),
            'http://localhost:8000/callback',
            'Demo Application'
          ],
          (err) => (err ? reject(err) : resolve())
        );
      } else {
        resolve();
      }
    });
  });
};

// ======================
// Helper Functions
// ======================
const generateAuthCode = () => crypto.randomBytes(16).toString('hex');

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_CONFIG.secret, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ======================
// Routes
// ======================
app.get('/favicon.ico', (req, res) => res.status(204).end());

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Frontend routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/auth', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

// Registration
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });

    const passwordHash = await bcrypt.hash(password, 12);

    db.run(
      `INSERT INTO users (email, password_hash) VALUES (?, ?)`,
      [email, passwordHash],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed'))
            return res.status(409).json({ error: 'Email already exists' });
          throw err;
        }

        const token = jwt.sign(
          { userId: this.lastID, email },
          JWT_CONFIG.secret,
          { expiresIn: JWT_CONFIG.expiresIn }
        );

        res.status(201).json({
          success: true,
          token,
          user: { id: this.lastID, email }
        });
      }
    );
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    db.get(
      `SELECT * FROM users WHERE email = ?`,
      [email],
      async (err, user) => {
        if (err || !user)
          return res.status(401).json({ error: 'Invalid credentials' });

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid)
          return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign(
          { userId: user.id, email: user.email },
          JWT_CONFIG.secret,
          { expiresIn: JWT_CONFIG.expiresIn }
        );

        res.json({
          success: true,
          token,
          user: { id: user.id, email: user.email }
        });
      }
    );
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OAuth authorize
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;

  db.get(
    `SELECT * FROM clients WHERE client_id = ? AND redirect_uri = ?`,
    [client_id, redirect_uri],
    (err, client) => {
      if (err || !client) {
        return res.status(400).json({ error: 'Invalid client or redirect URI' });
      }

      res.redirect(
        `/auth?client_id=${client_id}` +
        `&redirect_uri=${encodeURIComponent(redirect_uri)}` +
        `&state=${state || ''}`
      );
    }
  );
});

// OAuth token exchange
app.post('/oauth/token', (req, res) => {
  const { client_id, client_secret, code, redirect_uri } = req.body;

  db.get(
    `SELECT * FROM clients WHERE client_id = ? AND client_secret = ?`,
    [client_id, client_secret],
    (err, client) => {
      if (err || !client) {
        return res.status(401).json({ error: 'Invalid client credentials' });
      }

      db.get(
        `SELECT * FROM auth_codes 
         WHERE code = ? AND client_id = ? AND used = 0 AND expires_at > datetime('now')`,
        [code, client_id],
        (err, authCode) => {
          if (err || !authCode) {
            return res.status(400).json({ error: 'Invalid or expired code' });
          }

          db.run(
            `UPDATE auth_codes SET used = 1 WHERE code = ?`,
            [code],
            (err) => {
              if (err) return res.status(500).json({ error: 'Failed to update code' });

              const token = jwt.sign(
                { userId: authCode.user_id },
                JWT_CONFIG.secret,
                { expiresIn: JWT_CONFIG.expiresIn }
              );

              res.json({
                access_token: token,
                token_type: 'Bearer',
                expires_in: 3600
              });
            }
          );
        }
      );
    }
  );
});

// Generate auth code (for logged-in users)
app.post('/api/generate-code', authenticateToken, (req, res) => {
  const { client_id } = req.body;
  const code = generateAuthCode();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  db.get(`SELECT * FROM clients WHERE client_id = ?`, [client_id], (err, client) => {
    if (err || !client) {
      return res.status(400).json({ error: 'Invalid client ID' });
    }

    db.run(
      `INSERT INTO auth_codes (code, client_id, user_id, expires_at)
       VALUES (?, ?, ?, ?)`,
      [code, client_id, req.user.userId, expiresAt],
      (err) => {
        if (err) {
          console.error('Failed to generate code:', err);
          return res.status(500).json({ error: 'Failed to generate authorization code' });
        }
        res.json({ code, expires_at: expiresAt });
      }
    );
  });
});

// Protected user info
app.get('/api/user', authenticateToken, (req, res) => {
  db.get(
    `SELECT id, email FROM users WHERE id = ?`,
    [req.user.userId],
    (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    }
  );
});

// ======================
// Error Middleware & Server Start
// ======================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

initializeDatabase()
  .then(seedDemoClient)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`SSO Server running at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Startup failed:', err);
    process.exit(1);
  });
