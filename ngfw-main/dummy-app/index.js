const express = require('express');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.raw({ type: '*/*' })); // Accept all content types

// Basic demo endpoints
app.get('/info', (req, res) => {
  res.json({
    service: 'Dummy Backend',
    description: 'This is the protected service behind the AI‑NGFW gateway.',
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

// Use environment variable PORT or default to 9443
const PORT = process.env.PORT || 9443;

app.listen(PORT, () => {
  console.log(`Dummy Backend running at http://localhost:${PORT}`);
  console.log('Available endpoints: /info, /profile, /admin/secret, /honeypot/db-export');
});
