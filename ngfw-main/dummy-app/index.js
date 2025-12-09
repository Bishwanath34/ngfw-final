const https = require('https');
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const pem = require('pem');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.raw({ type: '*/*' })); // Accept all content types

// Generate self-signed cert for backend (one-time)
async function ensureCerts() {
  return new Promise((resolve, reject) => {
    if (fs.existsSync('backend-cert.pem') && fs.existsSync('backend-key.pem')) {
      resolve();
      return;
    }

    pem.createCertificate(
      { days: 365, selfSigned: true, keyBits: 2048 },
      (err, keys) => {
        if (err) return reject(err);
        fs.writeFileSync('backend-key.pem', keys.serviceKey);
        fs.writeFileSync('backend-cert.pem', keys.certificate);
        console.log('[BACKEND] Generated self-signed TLS certs (backend-key.pem, backend-cert.pem)');
        resolve();
      }
    );
  });
}

// Basic demo endpoints
app.get('/info', (req, res) => {
  res.json({
    service: 'Dummy HTTPS Backend',
    description:
      'This is the protected service behind the AI‑NGFW gateway.',
    docs: ['/info', '/profile', '/admin/secret', '/honeypot/db-export'],
    time: new Date().toISOString(),
  });
});

app.get('/profile', (req, res) => {
  const userId = req.headers['x-user-id'] || 'anonymous';
  const role = req.headers['x-user-role'] || 'guest';

  res.json({
    profile: {
      userId,
      role,
      email: `${userId}@example.gov.in`,
    },
    note: 'This profile is simulated data from the dummy backend.',
    time: new Date().toISOString(),
  });
});

app.get('/admin/secret', (req, res) => {
  res.json({
    secret: 'TOP SECRET ADMIN DATA',
    note: 'If you see this as a guest, firewall rules are bypassed!',
    sensitive: true,
    timestamp: new Date().toISOString(),
  });
});

app.get('/honeypot/db-export', (req, res) => {
  console.log(
    '[HONEYPOT] TRAPPED:',
    req.headers['x-user-id'],
    req.socket.remoteAddress
  );
  res.json({
    warning: 'Honeypot endpoint accessed!',
    message: 'This simulates a sensitive DB export endpoint.',
    fakeDump: {
      dbPassword: 'fakeadminpass',
      users: ['alice', 'bob', 'charlie'],
    },
    timestamp: new Date().toISOString(),
  });
});

async function startServer() {
  await ensureCerts();

  const tlsOptions = {
    key: fs.readFileSync('backend-key.pem'),
    cert: fs.readFileSync('backend-cert.pem'),
    requestCert: false,
    rejectUnauthorized: false,
  };

  // IMPORTANT: use 9443 so ML server can stay on 5000
  const PORT = 9443;

  https.createServer(tlsOptions, app).listen(PORT, () => {
    console.log(`Dummy Backend running at https://localhost:${PORT}`);
    console.log('Available endpoints: /info, /profile, /admin/secret, /honeypot/db-export');
    console.log('Remember to trust backend cert in browser/OS');
  });
}

startServer().catch(console.error);
