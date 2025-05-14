const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt'); // Assuming you added bcrypt as recommended

const dbPath = path.resolve(__dirname, 'database.db');

// Initialize the database
const dbinit = async () => {
  try {
    const db = await new sqlite3.Database(dbPath);
    const sql = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    twoFactorSecret TEXT,
    key TEXT NOT NULL,
    iv TEXT NOT NULL
  )
`;

    db.run(sql);
    return db;
  } catch (err) {
    console.error('Database initialization error:', err);
    throw err;
  }
};

// Authentication with CAPTCHA and 2FA verification
const authentication = async ({ username, password, captcha, captchaValue, twoFactorCode }) => {
  // Verify CAPTCHA
  if (captcha !== captchaValue) {
    throw new Error('Invalid CAPTCHA');
  }

  const db = await dbinit();
  const sql = 'SELECT * FROM users WHERE username = ?';
  return new Promise((resolve, reject) => {
    db.all(sql, [username], async (err, rows) => {
      db.close();
      if (err) {
        return reject(err);
      }
      if (rows.length === 0) {
        return resolve([]);
      }
      const user = rows[0];
      // Verify password (assuming passwords are hashed with bcrypt)
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return resolve([]);
      }
      // Verify 2FA code
      if (twoFactorCode && user.twoFactorSecret) {
        const verified = speakeasy.totp.verify({
          secret: user.twoFactorSecret,
          encoding: 'base32',
          token: twoFactorCode,
          window: 1 // Allow a 30-second window for clock drift
        });
        if (!verified) {
          return reject(new Error('Invalid 2FA code'));
        }
      }
      return resolve([user]);
    });
  });
};

// Signup with CAPTCHA and 2FA secret generation
const signup = async ({ username, password, captcha, captchaValue }) => {
  // Verify CAPTCHA
  if (captcha !== captchaValue) {
    throw new Error('Invalid CAPTCHA');
  }

  // Password validation
  const passwordRegex = /^(?=.\d)(?=.[a-z])(?=.*[A-Z]).{12,}$/;
  if (!passwordRegex.test(password)) {
    throw new Error('Password must be at least 12 characters long and contain at least one number, one uppercase letter, and one lowercase letter');
  }

  // Generate 2FA secret
  const secret = speakeasy.generateSecret({ length: 20 });

  const db = await dbinit();
  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = 'INSERT INTO users (username, password, twoFactorSecret) VALUES (?, ?, ?)';
  return new Promise((resolve, reject) => {
    db.run(sql, [username, hashedPassword, secret.base32], function (err) {
      db.close();
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return reject(new Error('Username already exists'));
        }
        return reject(err);
      }
      // Return the secret so we can generate a QR code
      return resolve({ success: true, secret: secret.base32 });
    });
  });
};

module.exports = { authenticate: authentication, signup: signup };