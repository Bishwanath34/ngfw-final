import React, { useState, useEffect } from 'react';
import axios from 'axios';

const GATEWAY_URL = 'https://localhost:4001';

function App() {
  // -------------------- ORIGINAL STATE (Traffic) --------------------
  const [userId, setUserId] = useState('alice');
  const [role, setRole] = useState('user');
  const [lastRequest, setLastRequest] = useState(null);
  const [loading, setLoading] = useState(false);

  const callApi = async (path) => {
    try {
      setLoading(true);
      setLastRequest(null);

      const res = await axios.get(`${GATEWAY_URL}/fw${path}`, {
        headers: {
          'x-user-id': userId || 'anonymous',
          'x-user-role': role || 'guest',
        },
        validateStatus: () => true,
      });

      setLastRequest({
        path,
        status: res.status,
        data: res.data,
      });
    } catch (err) {
      setLastRequest({
        path,
        status: 'ERROR',
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  // -------------------- ATTACK SIMULATORS --------------------

  // 1) DDoS Flood: 100 concurrent /info requests from bot clients
  const simulateDDoSAttack = async () => {
    const attackCount = 100;
    const promises = [];
    setLoading(true);
    setLastRequest(null);

    for (let i = 0; i < attackCount; i++) {
      promises.push(
        axios
          .get(`${GATEWAY_URL}/fw/info`, {
            headers: {
              'x-user-id': `bot${i}`,
              'x-user-role': 'guest',
            },
            timeout: 2000,
            validateStatus: () => true,
          })
          .catch(() => null) // Ignore individual errors; this is a stress test
      );
    }

    try {
      console.log('DDoS Attack Simulation: 100 concurrent /info requests');
      await Promise.allSettled(promises);
      setLastRequest({
        path: 'DDoS /info x100',
        status: 'SIMULATION',
        data: {
          message:
            'DDoS simulation sent 100 concurrent /info requests from guest bot clients. ' +
            'Check the AI–NGFW dashboard for rate limit / DDoS detections.',
        },
      });
    } catch (err) {
      setLastRequest({
        path: 'DDoS /info x100',
        status: 'ERROR',
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  // 2) SQL Injection probe: suspicious login URL
  const simulateSQLiAttack = async () => {
    const path = "/login?user=admin'%20OR%201=1--"; // URL-encoded ' OR 1=1 --
    try {
      setLoading(true);
      setLastRequest(null);

      const res = await axios.get(`${GATEWAY_URL}/fw${path}`, {
        headers: {
          'x-user-id': 'attacker-sqli',
          'x-user-role': 'guest',
        },
        validateStatus: () => true,
      });

      setLastRequest({
        path,
        status: res.status,
        data: res.data,
      });
    } catch (err) {
      setLastRequest({
        path,
        status: 'ERROR',
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  // 3) TLS Bot / Scanner: guest bot hammering /admin/secret with a TLS-bot flag header
  const simulateTLSBotAttack = async () => {
    const attackCount = 20;
    const promises = [];
    setLoading(true);
    setLastRequest(null);

    for (let i = 0; i < attackCount; i++) {
      promises.push(
        axios
          .get(`${GATEWAY_URL}/fw/admin/secret`, {
            headers: {
              'x-user-id': `tls-bot-${i}`,
              'x-user-role': 'guest',
              // Special simulation header the gateway uses to bump TLS risk
              'x-ngfw-sim-tls-bot': '1',
            },
            timeout: 2000,
            validateStatus: () => true,
          })
          .catch(() => null)
      );
    }

    try {
      console.log('TLS Bot / Scanner Simulation: 20 /admin/secret requests');
      await Promise.allSettled(promises);
      setLastRequest({
        path: 'TLS bot → /admin/secret x20',
        status: 'SIMULATION',
        data: {
          message:
            'Simulated TLS fingerprinting bot hitting /admin/secret. ' +
            'Gateway uses JA3-lite + TLS metadata + the sim header to classify and block.',
        },
      });
    } catch (err) {
      setLastRequest({
        path: 'TLS bot → /admin/secret x20',
        status: 'ERROR',
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  // -------------------- RBAC Manager --------------------
  const [rbac, setRbac] = useState({});
  const [roles, setRoles] = useState([]);
  const [selectedRole, setSelectedRole] = useState('');
  const [newAllowPath, setNewAllowPath] = useState('');
  const [newDenyPath, setNewDenyPath] = useState('');
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState('');

  const currentRoleRules = rbac[selectedRole] || { allow: [], deny: [] };

  const loadRBAC = async () => {
    try {
      setStatus('Loading RBAC from gateway...');
      const res = await axios.get(`${GATEWAY_URL}/admin/rbac`);
      const data = res.data || {};
      setRbac(data);
      const roleNames = Object.keys(data);
      setRoles(roleNames);
      if (!selectedRole && roleNames.length > 0) {
        setSelectedRole(roleNames[0]);
      }
      setStatus('RBAC loaded.');
      setTimeout(() => setStatus(''), 1500);
    } catch (err) {
      console.error('Failed to load RBAC', err);
      setStatus('Failed to load RBAC from gateway.');
    }
  };

  useEffect(() => {
    loadRBAC();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRoleChange = (e) => {
    setSelectedRole(e.target.value);
  };

  const handleAddAllow = () => {
    const p = newAllowPath.trim();
    if (!p || !selectedRole) return;
    setRbac((prev) => ({
      ...prev,
      [selectedRole]: {
        allow: [...(prev[selectedRole]?.allow || []), p],
        deny: [...(prev[selectedRole]?.deny || [])],
      },
    }));
    setNewAllowPath('');
  };

  const handleAddDeny = () => {
    const p = newDenyPath.trim();
    if (!p || !selectedRole) return;
    setRbac((prev) => ({
      ...prev,
      [selectedRole]: {
        allow: [...(prev[selectedRole]?.allow || [])],
        deny: [...(prev[selectedRole]?.deny || []), p],
      },
    }));
    setNewDenyPath('');
  };

  const handleRemoveAllow = (path) => {
    if (!selectedRole) return;
    setRbac((prev) => ({
      ...prev,
      [selectedRole]: {
        allow: (prev[selectedRole]?.allow || []).filter((p) => p !== path),
        deny: [...(prev[selectedRole]?.deny || [])],
      },
    }));
  };

  const handleRemoveDeny = (path) => {
    if (!selectedRole) return;
    setRbac((prev) => ({
      ...prev,
      [selectedRole]: {
        allow: [...(prev[selectedRole]?.allow || [])],
        deny: (prev[selectedRole]?.deny || []).filter((p) => p !== path),
      },
    }));
  };

  const handleSaveRBAC = async () => {
    try {
      setSaving(true);
      setStatus('Saving RBAC to gateway...');

      const res = await axios.post(
        `${GATEWAY_URL}/admin/rbac`,
        { rbac },
        { headers: { 'Content-Type': 'application/json' } }
      );

      if (res.status >= 400) {
        throw new Error(res.data?.error || 'Failed to save RBAC');
      }

      setStatus('RBAC updated successfully.');
      setTimeout(() => setStatus(''), 2000);
    } catch (err) {
      console.error('Failed to save RBAC', err);
      setStatus('Failed to save RBAC: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  // -------------------- UI --------------------
  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#020617',
        color: 'white',
        fontFamily:
          'system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
      }}
    >
      {/* Header */}
      <header
        style={{
          padding: '16px 24px',
          borderBottom: '1px solid #1f2937',
          marginBottom: 24,
        }}
      >
        <h1 style={{ margin: 0, fontSize: 24 }}>
          Dummy Web App (Protected by AI–NGFW)
        </h1>
        <p
          style={{
            margin: 0,
            marginTop: 4,
            color: '#9ca3af',
            fontSize: 14,
          }}
        >
          All requests go through the firewall gateway at{' '}
          <code style={{ color: '#e5e7eb' }}>
            https://localhost:4001/fw/…
          </code>
        </p>
      </header>

      <main style={{ maxWidth: 900, margin: '0 auto', padding: '0 16px 40px' }}>
        {/* User "session" section */}
        <section
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 8,
            border: '1px solid #1f2937',
            background: '#030712',
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>
            User Session
          </h2>
          <p style={{ marginTop: 0, color: '#9ca3af', fontSize: 14 }}>
            Pretend you are a user or an attacker. Choose an identity and
            role, then call different endpoints. The admin can watch
            everything on the security dashboard.
          </p>

          <div
            style={{
              display: 'flex',
              gap: 16,
              flexWrap: 'wrap',
              marginTop: 12,
            }}
          >
            <div style={{ flex: 1, minWidth: 180 }}>
              <label
                style={{ display: 'block', fontSize: 14, marginBottom: 4 }}
              >
                User ID
              </label>
              <input
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="alice, bob, attacker01…"
                style={{
                  width: '100%',
                  padding: '6px 8px',
                  borderRadius: 4,
                  border: '1px solid #374151',
                  background: '#020617',
                  color: 'white',
                }}
              />
            </div>

            <div style={{ flex: 1, minWidth: 180 }}>
              <label
                style={{ display: 'block', fontSize: 14, marginBottom: 4 }}
              >
                Role
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                style={{
                  width: '100%',
                  padding: '6px 8px',
                  borderRadius: 4,
                  border: '1px solid #374151',
                  background: '#020617',
                  color: 'white',
                }}
              >
                <option value="guest">guest</option>
                <option value="user">user</option>
                <option value="admin">admin</option>
              </select>
            </div>
          </div>
        </section>

        {/* Normal actions */}
        <section
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 8,
            border: '1px solid #1f2937',
            background: '#030712',
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>
            Normal Actions
          </h2>
          <p style={{ marginTop: 0, color: '#9ca3af', fontSize: 14 }}>
            These simulate normal user behavior. The firewall should allow
            them when RBAC + risk is satisfied.
          </p>

          <div
            style={{
              display: 'flex',
              gap: 12,
              flexWrap: 'wrap',
              marginTop: 12,
            }}
          >
            <button
              onClick={() => callApi('/info')}
              disabled={loading}
              style={{
                padding: '8px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#16a34a',
                color: 'white',
                cursor: 'pointer',
                fontSize: 14,
              }}
            >
              GET /info
            </button>

            <button
              onClick={() => callApi('/profile')}
              disabled={loading}
              style={{
                padding: '8px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#2563eb',
                color: 'white',
                cursor: 'pointer',
                fontSize: 14,
              }}
            >
              GET /profile
            </button>
          </div>
        </section>

        {/* Suspicious / attack actions */}
        <section
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 8,
            border: '1px solid #1f2937',
            background: '#030712',
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>
            Suspicious / Attack Actions
          </h2>
          <p style={{ marginTop: 0, color: '#9ca3af', fontSize: 14 }}>
            These endpoints simulate attackers probing admin areas or
            honeypots. The firewall should either block them or flag them.
          </p>

          <div
            style={{
              display: 'flex',
              gap: 12,
              flexWrap: 'wrap',
              marginTop: 12,
            }}
          >
            <button
              onClick={() => callApi('/admin/secret')}
              disabled={loading}
              style={{
                padding: '8px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#ea580c',
                color: 'white',
                cursor: 'pointer',
                fontSize: 14,
              }}
            >
              GET /admin/secret
            </button>

            <button
              onClick={() => callApi('/honeypot/db-export')}
              disabled={loading}
              style={{
                padding: '8px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#b91c1c',
                color: 'white',
                cursor: 'pointer',
                fontSize: 14,
              }}
            >
              GET /honeypot/db-export (Honeypot)
            </button>
          </div>
        </section>

        {/* Attack Simulators */}
        <section
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 8,
            border: '1px solid #1f2937',
            background: '#030712',
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>
            Attack Simulators
          </h2>
          <p style={{ marginTop: 0, color: '#9ca3af', fontSize: 14 }}>
            Use these buttons in the demo to show how the firewall reacts to
            different attack patterns: rate‑based DDoS, SQL injection, and
            TLS fingerprinting bots.
          </p>

          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
              marginTop: 12,
            }}
          >
            <button
              onClick={simulateDDoSAttack}
              disabled={loading}
              style={{
                padding: '10px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#dc2626',
                color: 'white',
                cursor: 'pointer',
                fontSize: 14,
                fontWeight: 600,
              }}
            >
              DDoS Flood → 100 × GET /info
            </button>

            <button
              onClick={simulateSQLiAttack}
              disabled={loading}
              style={{
                padding: '10px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#f97316',
                color: 'white',
                cursor: 'pointer',
                fontSize: 14,
                fontWeight: 600,
              }}
            >
              SQL Injection Probe → /login?user=admin&apos; OR 1=1 --
            </button>

            <button
              onClick={simulateTLSBotAttack}
              disabled={loading}
              style={{
                padding: '10px 12px',
                borderRadius: 6,
                border: 'none',
                background: '#7c3aed',
                color: 'white',
                cursor: 'pointer',
                fontSize: 14,
                fontWeight: 600,
              }}
            >
              TLS Bot / Scanner → 20 × /admin/secret
            </button>
          </div>
        </section>

        {/* Last response */}
        <section
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 8,
            border: '1px solid #1f2937',
            background: '#030712',
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>
            Last Response
          </h2>

          {loading && (
            <p style={{ color: '#9ca3af', fontSize: 14 }}>Sending request…</p>
          )}

          {!loading && !lastRequest && (
            <p style={{ color: '#6b7280', fontSize: 14 }}>
              No request yet. Click one of the buttons above to call the API
              via the firewall.
            </p>
          )}

          {!loading && lastRequest && (
            <div
              style={{
                fontFamily: 'monospace',
                fontSize: 13,
                whiteSpace: 'pre-wrap',
                background: '#020617',
                borderRadius: 6,
                padding: 10,
                border: '1px solid #1f2937',
              }}
            >
              <div style={{ marginBottom: 6 }}>
                <span style={{ color: '#9ca3af' }}>Path / Scenario:</span>{' '}
                {lastRequest.path}
              </div>
              <div style={{ marginBottom: 6 }}>
                <span style={{ color: '#9ca3af' }}>Status:</span>{' '}
                {lastRequest.status}
              </div>
              <div>
                <span style={{ color: '#9ca3af' }}>Body:</span>{' '}
                {JSON.stringify(lastRequest.data, null, 2)}
              </div>
            </div>
          )}
        </section>

        {/* ---------------- RBAC Manager Section ---------------- */}
        <section
          style={{
            padding: 16,
            borderRadius: 8,
            border: '1px solid #1f2937',
            background: '#030712',
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 12, fontSize: 18 }}>
            RBAC Manager (Edit Firewall Policies)
          </h2>
          <p style={{ marginTop: 0, color: '#9ca3af', fontSize: 14 }}>
            Configure which roles can access which paths. These settings are
            stored in the gateway and used in real-time for RBAC decisions.
          </p>

          {roles.length === 0 ? (
            <p style={{ color: '#6b7280', fontSize: 14 }}>
              No roles found. Check gateway RBAC configuration.
            </p>
          ) : (
            <div
              style={{
                marginBottom: 16,
                display: 'flex',
                gap: 16,
                alignItems: 'center',
                flexWrap: 'wrap',
              }}
            >
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: 14,
                    marginBottom: 4,
                  }}
                >
                  Select Role
                </label>
                <select
                  value={selectedRole}
                  onChange={handleRoleChange}
                  style={{
                    padding: '6px 8px',
                    borderRadius: 4,
                    border: '1px solid #374151',
                    background: '#020617',
                    color: 'white',
                  }}
                >
                  {roles.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>
              <button
                onClick={loadRBAC}
                style={{
                  padding: '6px 10px',
                  borderRadius: 6,
                  border: '1px solid #4b5563',
                  background: '#111827',
                  color: 'white',
                  cursor: 'pointer',
                  fontSize: 13,
                }}
              >
                Reload from Gateway
              </button>
            </div>
          )}

          {selectedRole && (
            <>
              <div
                style={{
                  display: 'flex',
                  gap: 16,
                  flexWrap: 'wrap',
                  marginBottom: 12,
                }}
              >
                {/* Allowed paths */}
                <div style={{ flex: 1, minWidth: 260 }}>
                  <h3 style={{ marginTop: 0, fontSize: 16 }}>Allowed Paths</h3>
                  <ul
                    style={{
                      listStyle: 'none',
                      paddingLeft: 0,
                      margin: '4px 0 8px 0',
                    }}
                  >
                    {(currentRoleRules.allow || []).map((p) => (
                      <li
                        key={p}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          fontSize: 13,
                          padding: '2px 0',
                        }}
                      >
                        <code>{p}</code>
                        <button
                          onClick={() => handleRemoveAllow(p)}
                          style={{
                            padding: '2px 6px',
                            borderRadius: 4,
                            border: 'none',
                            background: '#7f1d1d',
                            color: 'white',
                            cursor: 'pointer',
                            fontSize: 11,
                          }}
                        >
                          remove
                        </button>
                      </li>
                    ))}
                    {(!currentRoleRules.allow ||
                      currentRoleRules.allow.length === 0) && (
                      <li
                        style={{
                          fontSize: 13,
                          color: '#6b7280',
                          fontStyle: 'italic',
                        }}
                      >
                        No allowed paths defined.
                      </li>
                    )}
                  </ul>
                  <div
                    style={{
                      display: 'flex',
                      gap: 8,
                      marginTop: 4,
                    }}
                  >
                    <input
                      type="text"
                      placeholder="/info"
                      value={newAllowPath}
                      onChange={(e) => setNewAllowPath(e.target.value)}
                      style={{
                        flex: 1,
                        padding: '6px 8px',
                        borderRadius: 4,
                        border: '1px solid #374151',
                        background: '#020617',
                        color: 'white',
                      }}
                    />
                    <button
                      onClick={handleAddAllow}
                      style={{
                        padding: '6px 10px',
                        borderRadius: 4,
                        border: 'none',
                        background: '#2563eb',
                        color: 'white',
                        cursor: 'pointer',
                        fontSize: 12,
                      }}
                    >
                      + add
                    </button>
                  </div>
                  <p
                    style={{
                      marginTop: 4,
                      fontSize: 12,
                      color: '#9ca3af',
                    }}
                  >
                    Use <code>*</code> to allow everything (e.g. for admin).
                  </p>
                </div>

                {/* Denied paths */}
                <div style={{ flex: 1, minWidth: 260 }}>
                  <h3 style={{ marginTop: 0, fontSize: 16 }}>Denied Paths</h3>
                  <ul
                    style={{
                      listStyle: 'none',
                      paddingLeft: 0,
                      margin: '4px 0 8px 0',
                    }}
                  >
                    {(currentRoleRules.deny || []).map((p) => (
                      <li
                        key={p}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          fontSize: 13,
                          padding: '2px 0',
                        }}
                      >
                        <code>{p}</code>
                        <button
                          onClick={() => handleRemoveDeny(p)}
                          style={{
                            padding: '2px 6px',
                            borderRadius: 4,
                            border: 'none',
                            background: '#7f1d1d',
                            color: 'white',
                            cursor: 'pointer',
                            fontSize: 11,
                          }}
                        >
                          remove
                        </button>
                      </li>
                    ))}
                    {(!currentRoleRules.deny ||
                      currentRoleRules.deny.length === 0) && (
                      <li
                        style={{
                          fontSize: 13,
                          color: '#6b7280',
                          fontStyle: 'italic',
                        }}
                      >
                        No denied paths defined.
                      </li>
                    )}
                  </ul>
                  <div
                    style={{
                      display: 'flex',
                      gap: 8,
                      marginTop: 4,
                    }}
                  >
                    <input
                      type="text"
                      placeholder="/admin"
                      value={newDenyPath}
                      onChange={(e) => setNewDenyPath(e.target.value)}
                      style={{
                        flex: 1,
                        padding: '6px 8px',
                        borderRadius: 4,
                        border: '1px solid #374151',
                        background: '#020617',
                        color: 'white',
                      }}
                    />
                    <button
                      onClick={handleAddDeny}
                      style={{
                        padding: '6px 10px',
                        borderRadius: 4,
                        border: 'none',
                        background: '#ea580c',
                        color: 'white',
                        cursor: 'pointer',
                        fontSize: 12,
                      }}
                    >
                      + add
                    </button>
                  </div>
                  <p
                    style={{
                      marginTop: 4,
                      fontSize: 12,
                      color: '#9ca3af',
                    }}
                  >
                    Prefixes work: a rule <code>/admin</code> blocks{' '}
                    <code>/admin/secret</code> too.
                  </p>
                </div>
              </div>

              <div
                style={{
                  display: 'flex',
                  gap: 8,
                  marginTop: 12,
                  flexWrap: 'wrap',
                }}
              >
                <button
                  onClick={handleSaveRBAC}
                  disabled={saving}
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: 'none',
                    background: '#22c55e',
                    color: 'white',
                    cursor: 'pointer',
                    fontSize: 14,
                  }}
                >
                  {saving ? 'Saving…' : 'Save RBAC to Gateway'}
                </button>
              </div>
            </>
          )}

          {status && (
            <p
              style={{
                marginTop: 8,
                fontSize: 13,
                color: '#e5e7eb',
              }}
            >
              {status}
            </p>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
