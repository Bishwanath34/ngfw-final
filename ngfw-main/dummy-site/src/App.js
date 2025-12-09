import React, { useState } from 'react';
import axios from 'axios';
import { Container, Typography, Paper, Box, Button, Alert } from '@mui/material';

const GATEWAY_URL = 'https://localhost:4001';

function App() {
  const [status, setStatus] = useState('Ready to test…');
  const [loading, setLoading] = useState(false);

  const callGateway = async (path, label, { userId = 'alice', role = 'user' } = {}) => {
    setLoading(true);
    setStatus(`Calling ${path} as ${userId} (${role})…`);

    try {
      const res = await axios.get(`${GATEWAY_URL}/fw${path}`, {
        headers: {
          'x-user-id': userId,
          'x-user-role': role,
        },
        validateStatus: () => true,
      });

      setStatus(
        `${label} → HTTP ${res.status}\n` +
          JSON.stringify(res.data, null, 2)
      );
    } catch (err) {
      setStatus(`${label} → ERROR: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleNormal = () =>
    callGateway('/info', 'Normal user → GET /info', {
      userId: 'alice',
      role: 'user',
    });

  const handleAdmin = () =>
    callGateway('/admin/secret', 'Guest → GET /admin/secret', {
      userId: 'guest123',
      role: 'guest',
    });

  const handleHoneypot = () =>
    callGateway('/honeypot/db-export', 'Guest → GET /honeypot/db-export', {
      userId: 'guest123',
      role: 'guest',
    });

  const openLogs = () => {
    window.open(
      `${GATEWAY_URL}/admin/logs?limit=200`,
      '_blank',
      'noopener,noreferrer'
    );
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Paper elevation={3} sx={{ p: 4, mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          Dummy Site (Protected by AI‑NGFW)
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          Gateway:{' '}
          <code>{GATEWAY_URL}</code> | Backend:{' '}
          <code>https://localhost:9001</code>
        </Typography>

        <Alert severity="info" sx={{ mb: 3 }}>
          All traffic is sent through the AI‑NGFW gateway, inspected with
          ML + signatures, and then forwarded to the backend.
        </Alert>

        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
            mb: 3,
          }}
        >
          <Button
            variant="contained"
            color="success"
            disabled={loading}
            onClick={handleNormal}
          >
            Normal user → GET /info
          </Button>

          <Button
            variant="contained"
            color="warning"
            disabled={loading}
            onClick={handleAdmin}
          >
            Guest → GET /admin/secret (should be blocked)
          </Button>

          <Button
            variant="contained"
            color="error"
            disabled={loading}
            onClick={handleHoneypot}
          >
            Guest → GET /honeypot/db-export (honeypot)
          </Button>

          <Button
            variant="outlined"
            disabled={loading}
            onClick={openLogs}
          >
            Open /admin/logs in new tab
          </Button>
        </Box>

        <Paper
          variant="outlined"
          sx={{
            p: 2,
            bgcolor: '#0f172a',
            color: 'white',
          }}
        >
          <Typography variant="subtitle2" gutterBottom>
            Last Result
          </Typography>
          <Box
            sx={{
              p: 2,
              borderRadius: 1,
              bgcolor: '#020617',
              fontFamily: 'monospace',
              fontSize: 14,
              whiteSpace: 'pre-wrap',
              minHeight: 80,
            }}
          >
            {status}
          </Box>
        </Paper>
      </Paper>
    </Container>
  );
}

export default App;
