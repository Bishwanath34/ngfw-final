import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Box,
  Paper,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  ResponsiveContainer,
} from 'recharts';

const GATEWAY_URL = 'https://localhost:4001';

function App() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('all');
  const [chainOK, setChainOK] = useState(true);
  const [policyRecs, setPolicyRecs] = useState(null);

  // ---------- LOAD LOGS FROM GATEWAY ----------

  const loadLogs = async () => {
    try {
      const res = await axios.get(`${GATEWAY_URL}/admin/logs?limit=200`, {
        headers: { Accept: 'application/json' },
      });
      const list = res.data?.logs || res.data || [];
      setLogs(Array.isArray(list) ? list : []);
    } catch (err) {
      console.error('Error fetching logs', err);
    }
  };

  useEffect(() => {
    loadLogs();
    const id = setInterval(loadLogs, 1000);
    return () => clearInterval(id);
  }, []);

  // ---------- CHAIN INTEGRITY STATUS ----------

  const checkChainStatus = async () => {
    try {
      const res = await axios.get(`${GATEWAY_URL}/verify-chain`, {
        headers: { Accept: 'application/json' },
      });
      setChainOK(res.data?.ok === true);
    } catch (err) {
      console.error('Error checking chain status', err);
      setChainOK(false);
    }
  };

  useEffect(() => {
    checkChainStatus();
    const id = setInterval(checkChainStatus, 5000);
    return () => clearInterval(id);
  }, []);

  // ---------- POLICY RECOMMENDATIONS ----------

  const loadPolicyRecs = async () => {
    try {
      const res = await axios.get(`${GATEWAY_URL}/admin/policy/recommend`, {
        headers: { Accept: 'application/json' },
      });
      setPolicyRecs(res.data);
    } catch (err) {
      console.error('Error fetching policy recommendations', err);
    }
  };

  useEffect(() => {
    loadPolicyRecs();
    const id = setInterval(loadPolicyRecs, 15000);
    return () => clearInterval(id);
  }, []);

  // ---------- TRAFFIC SIMULATOR HELPERS ----------

  const simulateRequest = async (path, userId, role) => {
    try {
      await axios.get(`${GATEWAY_URL}/fw${path}`, {
        headers: {
          'x-user-id': userId,
          'x-user-role': role,
        },
        validateStatus: () => true,
      });
      await loadLogs();
    } catch (err) {
      console.error('Simulation error:', err);
      alert('Simulation failed. Check that gateway, backend and ML are running.');
    }
  };

  const simulateNormalUserInfo = () =>
    simulateRequest('/info', 'alice', 'user');

  const simulateSuspiciousGuestAdmin = () =>
    simulateRequest('/admin/secret', 'anonymous', 'guest');

  const simulateGuestAdminRBAC = () =>
    simulateRequest('/admin/secret', 'guest123', 'guest');

  // ---------- EXPORT LOGS (JSON / CSV) ----------

  const handleExport = async (format) => {
    try {
      const res = await axios.get(
        `${GATEWAY_URL}/admin/logs/export?format=${format}`,
        { responseType: 'blob' }
      );

      const blob = res.data;
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');

      link.href = url;
      link.download = format === 'csv' ? 'ngfw_logs.csv' : 'ngfw_logs.json';

      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error exporting logs', err);
      alert('Failed to export logs. Check gateway console for details.');
    }
  };

  // ---------- FILTERED LOGS + STATS ----------

  const filteredLogs = logs.filter((entry) => {
    if (filter === 'all') return true;
    const allowed =
      entry.statusCode < 400 && entry.decision?.allow !== false;
    if (filter === 'allowed') return allowed;
    if (filter === 'blocked') return !allowed;
    return true;
  });

  const displayLogs = [...filteredLogs].sort(
    (a, b) => new Date(b.time) - new Date(a.time)
  );

  const totalRequests = logs.length;
  const blockedCount = logs.filter(
    (e) => e.statusCode >= 400 || e.decision?.allow === false
  ).length;
  const highRiskCount = logs.filter(
    (e) =>
      e.decision?.label === 'high_risk' ||
      e.decision?.label === 'rbac_block'
  ).length;

  // ---------- PER-USER SUMMARY ----------

  const perUser = {};
  for (const e of logs) {
    const uid = e.context?.userId || 'anonymous';
    if (!perUser[uid]) {
      perUser[uid] = { total: 0, blocked: 0, highRisk: 0 };
    }
    perUser[uid].total += 1;
    if (e.statusCode >= 400 || e.decision?.allow === false) {
      perUser[uid].blocked += 1;
    }
    if (
      e.decision?.label === 'high_risk' ||
      e.decision?.label === 'rbac_block'
    ) {
      perUser[uid].highRisk += 1;
    }
  }
  const userSummary = Object.entries(perUser).map(([userId, stats]) => ({
    userId,
    ...stats,
  }));

  // ---------- ANALYTICS DATA (for charts) ----------

  const logsByTime = [...logs].sort(
    (a, b) => new Date(a.time) - new Date(b.time)
  );

  const timeSeriesData = logsByTime.map((e, idx) => ({
    index: idx + 1,
    timeLabel: new Date(e.time).toLocaleTimeString(),
    risk: e.decision?.risk ?? 0,
  }));

  const pathMap = {};
  for (const e of logs) {
    const p = e.context?.path || '/';
    if (!pathMap[p]) {
      pathMap[p] = { path: p, total: 0, allowed: 0, blocked: 0 };
    }
    pathMap[p].total += 1;
    const allowed =
      e.statusCode < 400 && e.decision?.allow !== false;
    if (allowed) pathMap[p].allowed += 1;
    else pathMap[p].blocked += 1;
  }
  const pathStats = Object.values(pathMap);

  const formatTime = (iso) => {
    if (!iso) return '-';
    try {
      return new Date(iso).toLocaleTimeString();
    } catch {
      return iso;
    }
  };

  // ---------- UI ----------

  return (
    <>
      <AppBar position="static" color="primary">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            AI–NGFW Dashboard
          </Typography>
          <Button color="inherit" onClick={loadLogs}>
            Refresh
          </Button>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        {/* Stats cards */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Paper sx={{ flex: 1, p: 2, bgcolor: '#111827', color: 'white' }}>
            <Typography variant="subtitle2">Total Requests</Typography>
            <Typography variant="h4">{totalRequests}</Typography>
          </Paper>
          <Paper sx={{ flex: 1, p: 2, bgcolor: '#065f46', color: 'white' }}>
            <Typography variant="subtitle2">Blocked</Typography>
            <Typography variant="h4">{blockedCount}</Typography>
          </Paper>
          <Paper sx={{ flex: 1, p: 2, bgcolor: '#7f1d1d', color: 'white' }}>
            <Typography variant="subtitle2">
              High-Risk / RBAC Blocks
            </Typography>
            <Typography variant="h4">{highRiskCount}</Typography>
          </Paper>
          <Paper
            sx={{
              flex: 1,
              p: 2,
              bgcolor: chainOK ? '#064e3b' : '#b91c1c',
              color: 'white',
            }}
          >
            <Typography variant="subtitle2">Log Integrity</Typography>
            <Typography variant="h5">
              {chainOK ? 'Verified' : 'TAMPERED!'}
            </Typography>
          </Paper>
        </Box>

        {/* Analytics */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Paper
            sx={{
              flex: 1,
              p: 2,
              minWidth: 300,
              bgcolor: '#020617',
              color: 'white',
            }}
          >
            <Typography variant="h6" gutterBottom>
              Risk over time
            </Typography>
            {timeSeriesData.length === 0 ? (
              <Typography variant="body2" sx={{ color: '#9ca3af' }}>
                No data yet. Use the simulator or dummy site to generate
                traffic.
              </Typography>
            ) : (
              <Box sx={{ width: '100%', height: 260 }}>
                <ResponsiveContainer>
                  <LineChart data={timeSeriesData}>
                    <CartesianGrid strokeDasharray="3 3' " />
                    <XAxis dataKey="timeLabel" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="risk"
                      name="Final Risk"
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            )}
          </Paper>

          <Paper
            sx={{
              flex: 1,
              p: 2,
              minWidth: 300,
              bgcolor: '#020617',
              color: 'white',
            }}
          >
            <Typography variant="h6" gutterBottom>
              Requests per path
            </Typography>
            {pathStats.length === 0 ? (
              <Typography variant="body2" sx={{ color: '#9ca3af' }}>
                No data yet.
              </Typography>
            ) : (
              <Box sx={{ width: '100%', height: 260 }}>
                <ResponsiveContainer>
                  <BarChart data={pathStats}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="path" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="allowed" name="Allowed" />
                    <Bar dataKey="blocked" name="Blocked" />
                  </BarChart>
                </ResponsiveContainer>
              </Box>
            )}
          </Paper>
        </Box>

        {/* Live feed + traffic simulator */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Paper
            sx={{
              flex: 2,
              p: 2,
              bgcolor: '#020617',
              color: 'white',
              fontFamily: 'monospace',
            }}
          >
            <Typography variant="h6" gutterBottom>
              Live traffic feed
            </Typography>
            <Box
              sx={{
                mt: 1,
                maxHeight: 220,
                overflowY: 'auto',
                borderRadius: 1,
                border: '1px solid #1f2937',
                p: 1,
                bgcolor: '#020617',
              }}
            >
              {displayLogs.slice(0, 20).map((entry, idx) => {
                const allowed =
                  entry.statusCode < 400 &&
                  entry.decision?.allow !== false;
                return (
                  <Box
                    key={idx}
                    sx={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: 1,
                      mb: 0.5,
                      fontSize: 12,
                    }}
                  >
                    <span style={{ color: '#6b7280' }}>
                      [{formatTime(entry.time)}]
                    </span>
                    <span>
                      {entry.context?.method}{' '}
                      {entry.context?.path}
                    </span>
                    <span style={{ color: '#9ca3af' }}>
                      (user: {entry.context?.userId || '?'},
                      {' '}
                      role: {entry.context?.role || '?'})
                    </span>
                    <span>
                      {allowed ? (
                        <span style={{ color: '#4ade80' }}>→ ALLOWED</span>
                      ) : (
                        <span style={{ color: '#f87171' }}>→ BLOCKED</span>
                      )}
                    </span>
                    <span style={{ color: '#e5e7eb' }}>
                      [{entry.decision?.label || 'normal'}]
                    </span>
                  </Box>
                );
              })}

              {displayLogs.length === 0 && (
                <Typography
                  variant="body2"
                  sx={{ color: '#6b7280' }}
                >
                  No traffic yet.
                </Typography>
              )}
            </Box>
          </Paper>

          <Paper
            sx={{
              flex: 1,
              p: 2,
              bgcolor: '#020617',
              color: 'white',
              minWidth: 260,
            }}
          >
            <Typography variant="h6" gutterBottom>
              Traffic simulator
            </Typography>
            <Typography
              variant="body2"
              sx={{ mb: 2, color: '#9ca3af' }}
            >
              Use these buttons during the demo to generate live events
              and show ML + RBAC + signature-based decisions.
            </Typography>

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
              <Button
                variant="contained"
                color="success"
                onClick={simulateNormalUserInfo}
              >
                NORMAL USER → /info
              </Button>

              <Button
                variant="contained"
                color="warning"
                onClick={simulateSuspiciousGuestAdmin}
              >
                SUSPICIOUS GUEST → /admin/secret
              </Button>

              <Button
                variant="contained"
                color="error"
                onClick={simulateGuestAdminRBAC}
              >
                GUEST → /admin/secret (RBAC BLOCK)
              </Button>
            </Box>
          </Paper>
        </Box>

        {/* Logs table */}
        <Paper sx={{ p: 2, bgcolor: '#020617' }}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              mb: 2,
              gap: 2,
            }}
          >
            <Typography variant="h6" color="white">
              Firewall traffic logs
            </Typography>

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              {/* Export buttons */}
              <Button
                variant="outlined"
                size="small"
                onClick={() => handleExport('json')}
                sx={{
                  borderColor: '#4b5563',
                  color: 'white',
                  '&:hover': { borderColor: '#9ca3af' },
                }}
              >
                Export JSON
              </Button>
              <Button
                variant="outlined"
                size="small"
                onClick={() => handleExport('csv')}
                sx={{
                  borderColor: '#4b5563',
                  color: 'white',
                  '&:hover': { borderColor: '#9ca3af' },
                }}
              >
                Export CSV
              </Button>

              {/* Filter buttons */}
              <ToggleButtonGroup
                value={filter}
                exclusive
                onChange={(_, v) => v && setFilter(v)}
                size="small"
                color="primary"
              >
                <ToggleButton
                  value="all"
                  sx={{
                    color: 'white',
                    borderColor: '#4b5563',
                    '&.Mui-selected': {
                      backgroundColor: '#2563eb',
                      color: '#fff',
                    },
                  }}
                >
                  ALL
                </ToggleButton>
                <ToggleButton
                  value="allowed"
                  sx={{
                    color: 'white',
                    borderColor: '#4b5563',
                    '&.Mui-selected': {
                      backgroundColor: '#16a34a',
                      color: '#fff',
                    },
                  }}
                >
                  ALLOWED
                </ToggleButton>
                <ToggleButton
                  value="blocked"
                  sx={{
                    color: 'white',
                    borderColor: '#4b5563',
                    '&.Mui-selected': {
                      backgroundColor: '#b91c1c',
                      color: '#fff',
                    },
                  }}
                >
                  BLOCKED
                </ToggleButton>
              </ToggleButtonGroup>
            </Box>
          </Box>

          <TableContainer sx={{ maxHeight: 420 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    Time
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    Path
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    User
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    Role
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    Risk
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    Decision
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    Status
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {displayLogs.map((entry, idx) => {
                  const allowed =
                    entry.statusCode < 400 &&
                    entry.decision?.allow !== false;
                  return (
                    <TableRow key={idx}>
                      <TableCell sx={{ color: 'white' }}>
                        {formatTime(entry.time)}
                      </TableCell>
                      <TableCell sx={{ color: 'white' }}>
                        {entry.context?.path}
                      </TableCell>
                      <TableCell sx={{ color: 'white' }}>
                        {entry.context?.userId}
                      </TableCell>
                      <TableCell sx={{ color: 'white' }}>
                        {entry.context?.role}
                      </TableCell>
                      <TableCell sx={{ color: 'white' }}>
                        <Chip
                          label={(entry.decision?.risk ?? 0).toFixed(2)}
                          size="small"
                          color={
                            entry.decision?.risk >= 0.9
                              ? 'error'
                              : entry.decision?.risk >= 0.6
                              ? 'warning'
                              : 'success'
                          }
                        />
                      </TableCell>
                      <TableCell sx={{ color: 'white' }}>
                        <Chip
                          label={entry.decision?.label || 'normal'}
                          size="small"
                          color={
                            entry.decision?.label === 'high_risk' ||
                            entry.decision?.label === 'rbac_block'
                              ? 'error'
                              : entry.decision?.label === 'medium_risk'
                              ? 'warning'
                              : 'success'
                          }
                        />
                      </TableCell>
                      <TableCell sx={{ color: 'white' }}>
                        <Chip
                          label={allowed ? 'Allowed' : 'Blocked'}
                          size="small"
                          color={allowed ? 'success' : 'error'}
                        />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* PER-USER RISK SUMMARY */}
        <Paper sx={{ p: 2, bgcolor: '#020617', mt: 3 }}>
          <Typography variant="h6" color="white" sx={{ mb: 2 }}>
            Per-user risk summary
          </Typography>
          <TableContainer sx={{ maxHeight: 260 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    User
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    Total Requests
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    Blocked
                  </TableCell>
                  <TableCell sx={{ color: 'white', bgcolor: '#020617' }}>
                    High-Risk / RBAC Blocks
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {userSummary.map((u) => (
                  <TableRow key={u.userId}>
                    <TableCell sx={{ color: 'white' }}>
                      {u.userId}
                    </TableCell>
                    <TableCell sx={{ color: 'white' }}>
                      {u.total}
                    </TableCell>
                    <TableCell sx={{ color: 'white' }}>
                      {u.blocked}
                    </TableCell>
                    <TableCell sx={{ color: 'white' }}>
                      {u.highRisk}
                    </TableCell>
                  </TableRow>
                ))}
                {userSummary.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={4}
                      sx={{ color: 'white', textAlign: 'center' }}
                    >
                      No data yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </Container>
    </>
  );
}

export default App;
