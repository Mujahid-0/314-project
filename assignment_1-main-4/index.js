const express = require("express");
const path = require("path");
const rateLimit = require('express-rate-limit');
const qrcode = require('qrcode');
const app = express();
const port = 3000;

app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

const database = require("./database/database.js");

// Rate-limit login and signup endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 requests per window
  message: 'Too many login attempts, please try again later'
});

const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 requests per window
  message: 'Too many signup attempts, please try again later'
});

app.use('/', express.static(path.join(__dirname, 'public', 'login')));
app.use('/signup', express.static(path.join(__dirname, 'public', 'signup')));

// Store temporary user data for 2FA step
const pendingLogins = new Map();

app.post('/login', loginLimiter, (req, res) => {
  const { username, password, captcha, 'captcha-value': captchaValue } = req.body;

  if (!captcha || !captchaValue) {
    return res.redirect('/?error=true&message=Missing CAPTCHA');
  }

  const user = {
    username: username,
    password: password,
    captcha: captcha,
    captchaValue: captchaValue
  };

  database.authenticate(user)
    .then((result) => {
      if (result.length === 0) {
        return res.redirect('/?error=true&message=Invalid username or password');
      }
      const userData = result[0];
      if (userData.twoFactorSecret) {
        // Store user data temporarily and redirect to 2FA page
        const sessionId = Date.now().toString();
        pendingLogins.set(sessionId, userData);
        return res.redirect(`/2fa?session=${sessionId}`);
      }
      // No 2FA, login successful
      res.json(result);
    })
    .catch((err) => {
      console.error('Login error:', err.message);
      res.redirect('/?error=true&message=' + encodeURIComponent(err.message));
    });
});

// Serve the 2FA page
app.get('/2fa', (req, res) => {
  const sessionId = req.query.session;
  if (!sessionId || !pendingLogins.has(sessionId)) {
    return res.redirect('/?error=true&message=Invalid session');
  }
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>2FA Verification</title>
        <link rel="stylesheet" href="/style.css">
    </head>
    <body>
        <header class="site-header">
            <h1>Two-Factor Authentication</h1>
        </header>
        <div class="login-container">
            <div class="error-message" hidden>
                Error: <span id="error-message-text">Invalid 2FA code</span>
            </div>
            <h2>Enter 2FA Code</h2>
            <form action="/verify-2fa" method="post">
                <input type="hidden" name="session" value="${sessionId}">
                <div class="input-group">
                    <label for="twoFactorCode">2FA Code:</label>
                    <input type="text" id="twoFactorCode" name="twoFactorCode" required>
                </div>
                <div class="btn-group">
                    <button type="submit" class="login-btn">Verify</button>
                </div>
            </form>
        </div>
        <script>
            const urlParams = new URLSearchParams(window.location.search);
            const error = urlParams.get('error');
            const message = urlParams.get('message');
            if (error) {
                const errorMessageText = document.getElementById('error-message-text');
                errorMessageText.textContent = message || 'Invalid 2FA code';
                document.querySelector('.error-message').style.display = 'block';
            }
        </script>
    </body>
    </html>
  `);
});

app.post('/verify-2fa', (req, res) => {
  const { session, twoFactorCode } = req.body;
  if (!session || !pendingLogins.has(session)) {
    return res.redirect('/?error=true&message=Invalid session');
  }

  const user = pendingLogins.get(session);
  database.authenticate({ ...user, twoFactorCode })
    .then((result) => {
      if (result.length === 0) {
        return res.redirect(`/2fa?session=${session}&error=true&message=Invalid 2FA code`);
      }
      pendingLogins.delete(session); // Clean up
      res.json(result); // Successful login
    })
    .catch((err) => {
      res.redirect(`/2fa?session=${session}&error=true&message=` + encodeURIComponent(err.message));
    });
});

app.post('/submitSignup', signupLimiter, (req, res) => {
  const { username, password, captcha, 'captcha-value': captchaValue } = req.body;

  if (!captcha || !captchaValue) {
    return res.redirect('/signup?error=true&message=Missing CAPTCHA');
  }

  const user = {
    username: username,
    password: password,
    captcha: captcha,
    captchaValue: captchaValue
  };

  database.signup(user)
    .then((result) => {
      if (!result.success) {
        return res.redirect('/signup?error=true&message=Failed to create user');
      }
      // Generate QR code for 2FA setup
      const otpauthUrl = `otpauth://totp/${username}?secret=${result.secret}&issuer=YourApp`;
      qrcode.toDataURL(otpauthUrl, (err, dataUrl) => {
        if (err) {
          console.error('QR code generation error:', err);
          return res.redirect('/signup?error=true&message=Failed to generate QR code');
        }
        res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>2FA Setup</title>
              <link rel="stylesheet" href="/style.css">
          </head>
          <body>
              <header class="site-header">
                  <h1>2FA Setup</h1>
              </header>
              <div class="signup-container">
                  <h2>User Created!</h2>
                  <p>Please scan the QR code below with your authenticator app (e.g., Google Authenticator) to set up 2FA.</p>
                  <img src="${dataUrl}" alt="2FA QR Code">
                  <p>After scanning, you can <a href="/">log in</a>.</p>
              </div>
          </body>
          </html>
        `);
      });
    })
    .catch((err) => {
      console.error('Signup error:', err.message);
      res.redirect('/signup?error=true&message=' + encodeURIComponent(err.message));
    });
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});