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

// ---------- DEPLOYED URLs ----------
const GATEWAY_URL = 'https://gate-jgv4.onrender.com';
const BACKEND_URL = 'https://app-dummy.onrender.com';
const ML_URL = 'https://final-ml-jiff.onrender.com';

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
      alert('Simulation failed. Check that gateway, backend, and ML are running.');
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
      {/* ... UI code remains unchanged ... */}
    </>
  );
}

export default App;
