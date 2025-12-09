import React, { useState, useEffect } from "react";
import axios from "axios";

// CHANGE THIS to your deployed gateway URL if needed:
const GATEWAY_URL = "https://localhost:4001";

function App() {
  // -------------------- ORIGINAL STATE (Traffic) --------------------
  const [userId, setUserId] = useState("alice");
  const [role, setRole] = useState("user");
  const [lastRequest, setLastRequest] = useState(null);
  const [loading, setLoading] = useState(false);

  const callApi = async (path) => {
    try {
      setLoading(true);
      setLastRequest(null);

      const res = await axios.get(`${GATEWAY_URL}/fw${path}`, {
        headers: {
          "x-user-id": userId || "anonymous",
          "x-user-role": role || "guest",
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
        status: "ERROR",
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  // -------------------- ATTACK SIMULATORS --------------------
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
              "x-user-id": `bot${i}`,
              "x-user-role": "guest",
            },
            timeout: 2000,
            validateStatus: () => true,
          })
          .catch(() => null)
      );
    }

    try {
      await Promise.allSettled(promises);
      setLastRequest({
        path: "DDoS /info x100",
        status: "SIMULATION",
        data: {
          message:
            "DDoS simulation: 100 concurrent /info requests. Check AI-NGFW detection logs.",
        },
      });
    } catch (err) {
      setLastRequest({
        path: "DDoS /info x100",
        status: "ERROR",
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  const simulateSQLiAttack = async () => {
    const path = `/login?user=admin'%20OR%201=1--`;
    try {
      setLoading(true);
      setLastRequest(null);

      const res = await axios.get(`${GATEWAY_URL}/fw${path}`, {
        headers: {
          "x-user-id": "attacker-sqli",
          "x-user-role": "guest",
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
        status: "ERROR",
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

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
              "x-user-id": `tls-bot-${i}`,
              "x-user-role": "guest",
              "x-ngfw-sim-tls-bot": "1",
            },
            timeout: 2000,
            validateStatus: () => true,
          })
          .catch(() => null)
      );
    }

    try {
      await Promise.allSettled(promises);
      setLastRequest({
        path: "TLS bot → /admin/secret x20",
        status: "SIMULATION",
        data: {
          message:
            "TLS bot / scanner simulated. Check AI-NGFW TLS fingerprinting mitigation logs.",
        },
      });
    } catch (err) {
      setLastRequest({
        path: "TLS bot → /admin/secret x20",
        status: "ERROR",
        data: { error: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  // -------------------- RBAC Manager --------------------
  const [rbac, setRbac] = useState({});
  const [roles, setRoles] = useState([]);
  const [selectedRole, setSelectedRole] = useState("");
  const [newAllowPath, setNewAllowPath] = useState("");
  const [newDenyPath, setNewDenyPath] = useState("");
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState("");

  const currentRoleRules = rbac[selectedRole] || { allow: [], deny: [] };

  const loadRBAC = async () => {
    try {
      setStatus("Loading RBAC...");
      const res = await axios.get(`${GATEWAY_URL}/admin/rbac`);
      const data = res.data || {};
      setRbac(data);
      const roleNames = Object.keys(data);
      setRoles(roleNames);
      if (!selectedRole && roleNames.length > 0) {
        setSelectedRole(roleNames[0]);
      }
      setStatus("RBAC loaded.");
      setTimeout(() => setStatus(""), 1500);
    } catch (err) {
      setStatus("Failed to load RBAC.");
    }
  };

  useEffect(() => {
    loadRBAC();
  }, []);

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
    setNewAllowPath("");
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
    setNewDenyPath("");
  };

  const handleRemoveAllow = (path) => {
    setRbac((prev) => ({
      ...prev,
      [selectedRole]: {
        allow: (prev[selectedRole]?.allow || []).filter((p) => p !== path),
        deny: [...(prev[selectedRole]?.deny || [])],
      },
    }));
  };

  const handleRemoveDeny = (path) => {
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
      setStatus("Saving RBAC...");

      await axios.post(
        `${GATEWAY_URL}/admin/rbac`,
        { rbac },
        { headers: { "Content-Type": "application/json" } }
      );

      setStatus("RBAC updated successfully.");
      setTimeout(() => setStatus(""), 2000);
    } catch (err) {
      setStatus("Failed to save RBAC: " + err.message);
    } finally {
      setSaving(false);
    }
  };

  // -------------------- UI --------------------
  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#020617",
        color: "white",
        fontFamily: "system-ui, sans-serif",
      }}
    >
      <header
        style={{
          padding: "16px 24px",
          borderBottom: "1px solid #1f2937",
          marginBottom: 24,
        }}
      >
        <h1 style={{ margin: 0, fontSize: 24 }}>
          Dummy Web App (Protected by AI-NGFW)
        </h1>
      </header>

      <main style={{ maxWidth: 900, margin: "0 auto", padding: 16 }}>
        {/* User Session */}
        <section
          style={{
            padding: 16,
            marginBottom: 24,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ fontSize: 18 }}>User Session</h2>
          <div style={{ display: "flex", gap: 16, marginTop: 12 }}>
            <input
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="alice, bob…"
              style={{
                padding: 8,
                borderRadius: 4,
                border: "1px solid #374151",
                background: "#020617",
                color: "white",
                flex: 1,
              }}
            />

            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              style={{
                padding: 8,
                borderRadius: 4,
                border: "1px solid #374151",
                background: "#020617",
                color: "white",
              }}
            >
              <option value="guest">guest</option>
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </div>
        </section>

        {/* Normal */}
        <section
          style={{
            padding: 16,
            marginBottom: 24,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ fontSize: 18 }}>Normal Actions</h2>
          <button
            onClick={() => callApi("/info")}
            disabled={loading}
            style={{
              padding: "8px 12px",
              background: "#16a34a",
              borderRadius: 6,
              border: "none",
              color: "white",
              marginRight: 10,
              cursor: "pointer",
            }}
          >
            GET /info
          </button>

          <button
            onClick={() => callApi("/profile")}
            disabled={loading}
            style={{
              padding: "8px 12px",
              background: "#2563eb",
              borderRadius: 6,
              border: "none",
              color: "white",
              cursor: "pointer",
            }}
          >
            GET /profile
          </button>
        </section>

        {/* Suspicious */}
        <section
          style={{
            padding: 16,
            marginBottom: 24,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ fontSize: 18 }}>Suspicious / Attack Actions</h2>
          <button
            onClick={() => callApi("/admin/secret")}
            disabled={loading}
            style={{
              padding: "8px 12px",
              background: "#ea580c",
              borderRadius: 6,
              border: "none",
              color: "white",
              marginRight: 10,
            }}
          >
            GET /admin/secret
          </button>

          <button
            onClick={() => callApi("/honeypot/db-export")}
            disabled={loading}
            style={{
              padding: "8px 12px",
              background: "#b91c1c",
              borderRadius: 6,
              border: "none",
              color: "white",
            }}
          >
            GET /honeypot/db-export
          </button>
        </section>

        {/* Attack Simulators */}
        <section
          style={{
            padding: 16,
            marginBottom: 24,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ fontSize: 18 }}>Attack Simulators</h2>

          <button
            onClick={simulateDDoSAttack}
            disabled={loading}
            style={{
              padding: "10px 12px",
              background: "#dc2626",
              borderRadius: 6,
              border: "none",
              color: "white",
              marginBottom: 8,
              width: "100%",
            }}
          >
            DDoS → 100 × GET /info
          </button>

          <button
            onClick={simulateSQLiAttack}
            disabled={loading}
            style={{
              padding: "10px 12px",
              background: "#f97316",
              borderRadius: 6,
              border: "none",
              color: "white",
              marginBottom: 8,
              width: "100%",
            }}
          >
            SQL Injection → /login?admin' OR 1=1 --
          </button>

          <button
            onClick={simulateTLSBotAttack}
            disabled={loading}
            style={{
              padding: "10px 12px",
              background: "#7c3aed",
              borderRadius: 6,
              border: "none",
              color: "white",
              width: "100%",
            }}
          >
            TLS Bot → 20 × /admin/secret
          </button>
        </section>

        {/* Last Response */}
        <section
          style={{
            padding: 16,
            marginBottom: 24,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ fontSize: 18 }}>Last Response</h2>
          {loading && <p>Sending request…</p>}
          {!loading && !lastRequest && <p>No requests yet.</p>}
          {!loading && lastRequest && (
            <pre
              style={{
                background: "#020617",
                padding: 12,
                borderRadius: 6,
                border: "1px solid #1f2937",
                fontSize: 13,
              }}
            >
              {JSON.stringify(lastRequest, null, 2)}
            </pre>
          )}
        </section>

        {/* RBAC Manager */}
        <section
          style={{
            padding: 16,
            borderRadius: 8,
            border: "1px solid #1f2937",
            background: "#030712",
          }}
        >
          <h2 style={{ fontSize: 18 }}>RBAC Manager</h2>
          {roles.length === 0 ? (
            <p>No roles found.</p>
          ) : (
            <>
              <select
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value)}
                style={{
                  padding: 8,
                  borderRadius: 4,
                  background: "#020617",
                  color: "white",
                  border: "1px solid #374151",
                }}
              >
                {roles.map((r) => (
                  <option key={r}>{r}</option>
                ))}
              </select>

              <button
                onClick={loadRBAC}
                style={{
                  marginLeft: 12,
                  padding: "6px 10px",
                  borderRadius: 6,
                  background: "#111827",
                  border: "1px solid #4b5563",
                  color: "white",
                  cursor: "pointer",
                }}
              >
                Reload
              </button>

              <div style={{ display: "flex", marginTop: 16, gap: 16 }}>
                <div style={{ flex: 1 }}>
                  <h3>Allowed Paths</h3>
                  <ul>
                    {currentRoleRules.allow.map((p) => (
                      <li key={p}>
                        <code>{p}</code>
                        <button
                          onClick={() => handleRemoveAllow(p)}
                          style={{
                            marginLeft: 8,
                            background: "#7f1d1d",
                            color: "white",
                            padding: "2px 6px",
                            borderRadius: 4,
                            border: "none",
                          }}
                        >
                          remove
                        </button>
                      </li>
                    ))}
                  </ul>
                  <input
                    placeholder="/info"
                    value={newAllowPath}
                    onChange={(e) => setNewAllowPath(e.target.value)}
                    style={{
                      padding: 8,
                      background: "#020617",
                      border: "1px solid #374151",
                      borderRadius: 4,
                      color: "white",
                      width: "70%",
                    }}
                  />
                  <button
                    onClick={handleAddAllow}
                    style={{
                      padding: "6px 10px",
                      borderRadius: 4,
                      background: "#2563eb",
                      border: "none",
                      color: "white",
                      marginLeft: 8,
                    }}
                  >
                    add
                  </button>
                </div>

                <div style={{ flex: 1 }}>
                  <h3>Denied Paths</h3>
                  <ul>
                    {currentRoleRules.deny.map((p) => (
                      <li key={p}>
                        <code>{p}</code>
                        <button
                          onClick={() => handleRemoveDeny(p)}
                          style={{
                            marginLeft: 8,
                            background: "#7f1d1d",
                            color: "white",
                            padding: "2px 6px",
                            borderRadius: 4,
                            border: "none",
                          }}
                        >
                          remove
                        </button>
                      </li>
                    ))}
                  </ul>
                  <input
                    placeholder="/admin"
                    value={newDenyPath}
                    onChange={(e) => setNewDenyPath(e.target.value)}
                    style={{
                      padding: 8,
                      background: "#020617",
                      border: "1px solid #374151",
                      borderRadius: 4,
                      color: "white",
                      width: "70%",
                    }}
                  />
                  <button
                    onClick={handleAddDeny}
                    style={{
                      padding: "6px 10px",
                      borderRadius: 4,
                      background: "#dc2626",
                      border: "none",
                      color: "white",
                      marginLeft: 8,
                    }}
                  >
                    add
                  </button>
                </div>
              </div>

              <button
                onClick={handleSaveRBAC}
                disabled={saving}
                style={{
                  marginTop: 16,
                  padding: "10px 12px",
                  borderRadius: 6,
                  background: "#059669",
                  border: "none",
                  color: "white",
                  width: "100%",
                  fontWeight: 600,
                }}
              >
                Save RBAC
              </button>

              {status && <p style={{ marginTop: 10 }}>{status}</p>}
            </>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
