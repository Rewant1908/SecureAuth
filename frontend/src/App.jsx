import { useState } from "react";

export default function App() {
  const [page, setPage] = useState("simulator");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const scenarios = {
    normal:     { username: "john.doe",        password: "SecurePass123!" },
    suspicious: { username: "admin",           password: "password123"    },
    attack:     { username: "'; DROP TABLE;--", password: "hacker"        },
  };

  const handleScenario = (type) => {
    setUsername(scenarios[type].username);
    setPassword(scenarios[type].password);
  };

  const handleAnalyze = async () => {
    setLoading(true);
    await new Promise(r => setTimeout(r, 1200));
    setResult({
      status: "challenge_required",
      auth_event_id: "ae_938k2l_sentinel",
      risk_assessment: {
        score: 75,
        level: "MEDIUM",
        factors: ["vpn_detected", "device_mismatch"]
      },
      decision: {
        action: "REQUIRE_MFA",
        mfa_types: ["SMS", "TOTP"],
        timestamp: "2023-10-27T14:02:11Z"
      }
    });
    setLoading(false);
    setPage("dashboard");
  };

  return (
      <div style={{ minHeight: "100vh", background: "#0b1326", color: "#dae2fd", fontFamily: "'Inter', sans-serif" }}>

        {/* ── NAVBAR ── */}
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, zIndex: 100,
          height: "56px",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "0 40px",
          background: "rgba(11,19,38,0.75)",
          backdropFilter: "blur(20px)",
          borderBottom: "1px solid rgba(255,255,255,0.04)"
        }}>
        <span style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 800, fontSize: "18px", color: "#dae2fd" }}>
          SecureAuth
        </span>

          <div style={{ display: "flex", gap: "32px", fontSize: "14px" }}>
          <span
              onClick={() => setPage("simulator")}
              style={{ cursor: "pointer", color: page === "simulator" ? "#4cd6ff" : "#8a97b8", fontWeight: page === "simulator" ? 600 : 400, transition: "color 0.2s" }}
          >
            Login Simulator
          </span>
            <span
                onClick={() => setPage("dashboard")}
                style={{ cursor: "pointer", color: page === "dashboard" ? "#4cd6ff" : "#8a97b8", fontWeight: page === "dashboard" ? 600 : 400, transition: "color 0.2s" }}
            >
            Result Dashboard
          </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            {/* shield icon */}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8a97b8" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            {/* user icon */}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8a97b8" strokeWidth="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
            <div style={{
              background: "linear-gradient(135deg, #4cd6ff, #009dc1)",
              color: "#001f2a", padding: "5px 14px", borderRadius: "999px",
              fontSize: "11px", fontWeight: 800, letterSpacing: "0.06em"
            }}>
              PROTECTED
            </div>
          </div>
        </div>

        {/* ── SIDEBAR ── */}
        <div style={{
          position: "fixed", top: 0, left: 0, bottom: 0,
          width: "240px", zIndex: 50,
          background: "#131b2e",
          display: "flex", flexDirection: "column",
          padding: "80px 20px 32px"
        }}>
          <div style={{ marginBottom: "36px" }}>
            <div style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 800, fontSize: "16px", color: "#dae2fd" }}>SecureAuth</div>
            <div style={{ fontSize: "10px", fontWeight: 600, letterSpacing: "0.12em", color: "#4cd6ff", marginTop: "4px" }}>AI SENTINEL ACTIVE</div>
          </div>

          <nav style={{ display: "flex", flexDirection: "column", gap: "4px", flex: 1 }}>
            <NavItem icon="fingerprint" label="Login Simulator" active={page === "simulator"} onClick={() => setPage("simulator")} />
            <NavItem icon="dashboard"   label="Result Dashboard" active={page === "dashboard"} onClick={() => setPage("dashboard")} />
          </nav>

          <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: "20px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "20px" }}>
              <div style={{
                width: "32px", height: "32px", borderRadius: "50%",
                background: "#2d3449", display: "flex", alignItems: "center", justifyContent: "center"
              }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8a97b8" strokeWidth="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
              </div>
              <div>
                <div style={{ fontSize: "13px", fontWeight: 600, color: "#dae2fd" }}>System Operator</div>
                <div style={{ fontSize: "11px", color: "#8a97b8" }}>Root Access</div>
              </div>
            </div>

            <NavItem icon="settings" label="Settings"  active={false} onClick={() => {}} />
            <NavItem icon="demo"     label="Demo Mode" active={false} onClick={() => {}} />
          </div>
        </div>

        {/* ── PAGE CONTENT ── */}
        <div style={{ marginLeft: "240px", paddingTop: "56px", minHeight: "100vh" }}>
          {page === "simulator"
              ? <SimulatorPage username={username} password={password} loading={loading}
                               setUsername={setUsername} setPassword={setPassword}
                               onAnalyze={handleAnalyze} onScenario={handleScenario} />
              : <DashboardPage result={result} onBack={() => setPage("simulator")} />
          }
        </div>
      </div>
  );
}

/* ── NAV ITEM ───────────────────────────────────────────────── */
function NavItem({ icon, label, active, onClick }) {
  const icons = {
    fingerprint: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22C6 22 2 17.5 2 12S6 2 12 2s10 4.5 10 10"/><path d="M12 18c-2.5 0-4-2-4-4s1.5-4 4-4 4 2 4 4"/><path d="M12 14v.01"/></svg>,
    dashboard:   <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>,
    settings:    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
    demo:        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>,
  };

  return (
      <div onClick={onClick} style={{
        display: "flex", alignItems: "center", gap: "10px",
        padding: "10px 12px", borderRadius: "10px", cursor: "pointer",
        background: active ? "rgba(76,214,255,0.1)" : "transparent",
        color: active ? "#4cd6ff" : "#8a97b8",
        fontSize: "14px", fontWeight: active ? 600 : 400,
        transition: "background 0.2s, color 0.2s",
        marginBottom: "2px"
      }}
           onMouseEnter={e => { if (!active) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
           onMouseLeave={e => { if (!active) e.currentTarget.style.background = "transparent"; }}
      >
        {icons[icon]}
        {label}
      </div>
  );
}

/* ── SIMULATOR PAGE ─────────────────────────────────────────── */
function SimulatorPage({ username, password, loading, setUsername, setPassword, onAnalyze, onScenario }) {
  return (
      <div style={{ padding: "56px 64px", maxWidth: "900px" }}>

        <div style={{ marginBottom: "48px" }}>
          <h1 style={{ fontFamily: "'Manrope',sans-serif", fontSize: "52px", fontWeight: 800, color: "#dae2fd", lineHeight: 1.1, marginBottom: "16px" }}>
            Simulate Access
          </h1>
          <p style={{ fontSize: "16px", color: "#8a97b8", lineHeight: 1.6, maxWidth: "480px" }}>
            Run AI-driven behavioral analysis on authentication attempts to detect anomaly patterns.
          </p>
        </div>

        {/* Login Card */}
        <div style={{
          background: "#171f33", borderRadius: "24px", padding: "40px",
          boxShadow: "12px 24px 48px rgba(218,226,253,0.06)",
          maxWidth: "520px", marginBottom: "32px"
        }}>
          {/* Username */}
          <div style={{ marginBottom: "20px" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "8px" }}>
              Username
            </div>
            <div style={{
              display: "flex", alignItems: "center", gap: "12px",
              background: "#1e2840", borderRadius: "10px", padding: "0 16px",
              border: "1px solid transparent", transition: "border-color 0.2s"
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4a5580" strokeWidth="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
              <input
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder="e.g. sentinel_operator"
                  style={{ flex: 1, padding: "14px 0", background: "transparent", border: "none", outline: "none", color: "#dae2fd", fontSize: "15px" }}
              />
            </div>
          </div>

          {/* Password */}
          <div style={{ marginBottom: "28px" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "8px" }}>
              Password
            </div>
            <div style={{
              display: "flex", alignItems: "center", gap: "12px",
              background: "#1e2840", borderRadius: "10px", padding: "0 16px"
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4a5580" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              <input
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  type="password"
                  placeholder="••••••••••••"
                  style={{ flex: 1, padding: "14px 0", background: "transparent", border: "none", outline: "none", color: "#dae2fd", fontSize: "15px" }}
              />
            </div>
          </div>

          {/* Analyze Button */}
          <button
              onClick={onAnalyze}
              disabled={loading}
              style={{
                width: "100%", padding: "16px",
                background: loading ? "#1e2840" : "linear-gradient(135deg, #4cd6ff, #009dc1)",
                border: "none", borderRadius: "10px",
                color: loading ? "#8a97b8" : "#001f2a",
                fontFamily: "'Manrope',sans-serif", fontSize: "15px", fontWeight: 700,
                cursor: loading ? "not-allowed" : "pointer",
                display: "flex", alignItems: "center", justifyContent: "center", gap: "8px",
                transition: "transform 0.15s, box-shadow 0.15s",
                boxShadow: loading ? "none" : "0 0 24px rgba(76,214,255,0.2)"
              }}
              onMouseDown={e => { if (!loading) e.currentTarget.style.transform = "scale(0.98)"; }}
              onMouseUp={e => { e.currentTarget.style.transform = "scale(1)"; }}
          >
            {loading ? (
                <>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ animation: "spin 1s linear infinite" }}><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
                  Analyzing...
                </>
            ) : (
                <>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                  Analyze Login
                </>
            )}
          </button>
        </div>

        {/* Demo Scenarios */}
        <div style={{ background: "#131b2e", borderRadius: "16px", padding: "28px", maxWidth: "520px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#4cd6ff" strokeWidth="2"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2v-4M9 21H5a2 2 0 0 1-2-2v-4m0 0h18"/></svg>
              <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8" }}>Demo Scenarios</span>
            </div>
            <span style={{ fontSize: "11px", color: "#4a5580", letterSpacing: "0.06em", textTransform: "uppercase" }}>Select Preset</span>
          </div>

          <div style={{ display: "flex", gap: "12px" }}>
            <ScenarioBtn label="Normal"     color="#4cffb0" onClick={() => onScenario("normal")} />
            <ScenarioBtn label="Suspicious" color="#ffc04c" onClick={() => onScenario("suspicious")} />
            <ScenarioBtn label="Attack"     color="#ffb4ab" onClick={() => onScenario("attack")} />
          </div>
        </div>

        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
  );
}

function ScenarioBtn({ label, color, onClick }) {
  const icons = {
    Normal:     <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>,
    Suspicious: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    Attack:     <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>,
  };

  return (
      <div
          onClick={onClick}
          style={{
            flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "10px",
            padding: "20px 12px", background: "#171f33", borderRadius: "12px",
            cursor: "pointer", border: "1px solid transparent", transition: "all 0.2s"
          }}
          onMouseEnter={e => { e.currentTarget.style.background = "#1e2840"; e.currentTarget.style.borderColor = `${color}33`; e.currentTarget.style.transform = "translateY(-2px)"; }}
          onMouseLeave={e => { e.currentTarget.style.background = "#171f33"; e.currentTarget.style.borderColor = "transparent"; e.currentTarget.style.transform = "translateY(0)"; }}
      >
        {icons[label]}
        <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "#8a97b8" }}>{label}</span>
      </div>
  );
}

/* ── DASHBOARD PAGE ─────────────────────────────────────────── */
function DashboardPage({ result }) {
  const score = result?.risk_assessment?.score ?? 75;
  const level = result?.risk_assessment?.level ?? "MEDIUM";

  const ringColor = level === "HIGH" ? "#ffb4ab" : level === "MEDIUM" ? "#ffc04c" : "#4cffb0";
  const circumference = 2 * Math.PI * 52;
  const dashOffset = circumference - (score / 100) * circumference;

  const logs = [
    { time: "14:02:11", title: "Anomaly Detected",   desc: "Browser fingerprint mismatch on primary node.", highlight: false },
    { time: "14:02:10", title: "Access Challenged",  desc: "Risk score threshold (60) exceeded. Initiating MFA.", highlight: false },
    { time: "14:02:08", title: "Auth Violation",     desc: "Attempted access from blacklisted VPN subnet.", highlight: true  },
  ];

  return (
      <div style={{ padding: "40px 48px" }}>

        {/* Top Row — 3 cards */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "20px", marginBottom: "24px" }}>

          {/* Risk Score Ring */}
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "36px", display: "flex", flexDirection: "column", alignItems: "center", gap: "16px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <svg width="140" height="140" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="52" fill="none" stroke="#1e2840" strokeWidth="10"/>
              <circle cx="60" cy="60" r="52" fill="none" stroke={ringColor} strokeWidth="10"
                      strokeDasharray={circumference} strokeDashoffset={dashOffset}
                      strokeLinecap="round" transform="rotate(-90 60 60)"
                      style={{ transition: "stroke-dashoffset 1s ease" }}
              />
              <text x="60" y="56" textAnchor="middle" fill="#dae2fd" fontSize="26" fontWeight="800" fontFamily="Manrope,sans-serif">{score}</text>
              <text x="60" y="72" textAnchor="middle" fill="#8a97b8" fontSize="9" fontFamily="Inter,sans-serif" letterSpacing="1">RISK SCORE</text>
            </svg>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: ringColor }}/>
              <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: ringColor }}>
              {level} RISK DETECTED
            </span>
            </div>
          </div>

          {/* Security Decision */}
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "36px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "20px" }}>Security Decision</div>
            <div style={{
              display: "flex", alignItems: "center", gap: "10px",
              background: "rgba(255,180,171,0.1)", border: "1px solid rgba(255,180,171,0.25)",
              borderRadius: "10px", padding: "14px 18px", marginBottom: "20px"
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffb4ab" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <span style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 700, fontSize: "14px", color: "#ffc04c", letterSpacing: "0.06em" }}>MFA REQUIRED</span>
            </div>
            <p style={{ fontSize: "13px", color: "#8a97b8", lineHeight: 1.7 }}>
              The AI Sentinel detected unusual login patterns. Standard authentication bypassed, secondary verification required to proceed.
            </p>
          </div>

          {/* Threat Level */}
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "36px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "20px" }}>Threat Level</div>
            <div style={{ display: "flex", alignItems: "baseline", gap: "10px", marginBottom: "24px" }}>
              <span style={{ fontFamily: "'Manrope',sans-serif", fontSize: "40px", fontWeight: 800, color: "#ffc04c" }}>Elevated</span>
              <span style={{ fontSize: "13px", color: "#8a97b8" }}>Zone B</span>
            </div>
            <div style={{ background: "#1e2840", borderRadius: "4px", height: "6px", overflow: "hidden" }}>
              <div style={{ width: `${score}%`, height: "100%", background: "linear-gradient(to right, #ffc04c, #ffb4ab)", borderRadius: "4px", transition: "width 1s ease" }}/>
            </div>
          </div>
        </div>

        {/* Bottom Row */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "24px" }}>

          {/* Session Details */}
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "32px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "28px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4cd6ff" strokeWidth="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                <span style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 700, fontSize: "16px" }}>Session Details</span>
              </div>
              <span style={{
                background: "rgba(76,214,255,0.1)", border: "1px solid rgba(76,214,255,0.25)",
                color: "#4cd6ff", padding: "3px 10px", borderRadius: "4px",
                fontSize: "11px", fontFamily: "'JetBrains Mono',monospace", fontWeight: 500
              }}>LIVE</span>
            </div>

            {[
              { label: "MFA Method",    value: "SMS OTP",        accent: false },
              { label: "Device ID",     value: "auth_dev_9921_x", accent: true  },
              { label: "Geo-Location",  value: "San Francisco, US", accent: false },
              { label: "Token Expiry",  value: "14m 22s",         accent: false },
            ].map((row, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 0", borderBottom: i < 3 ? "1px solid rgba(255,255,255,0.04)" : "none" }}>
                  <span style={{ fontSize: "13px", color: "#8a97b8" }}>{row.label}</span>
                  <span style={{ fontSize: "13px", fontWeight: 500, color: row.accent ? "#4cd6ff" : "#dae2fd", fontFamily: row.accent ? "'JetBrains Mono',monospace" : "inherit" }}>{row.value}</span>
                </div>
            ))}
          </div>

          {/* Security Logs */}
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "32px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "28px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4cd6ff" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <span style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 700, fontSize: "16px" }}>Security Logs</span>
              </div>
              <button style={{ background: "transparent", border: "none", cursor: "pointer", color: "#8a97b8" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-.18-3.36"/></svg>
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              {logs.map((log, i) => (
                  <div key={i} style={{
                    padding: "14px 16px", borderRadius: "10px",
                    background: log.highlight ? "rgba(255,180,171,0.08)" : "transparent",
                    border: log.highlight ? "1px solid rgba(255,180,171,0.15)" : "1px solid transparent"
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "4px" }}>
                      <span style={{ fontSize: "11px", fontFamily: "'JetBrains Mono',monospace", color: "#4a5580" }}>{log.time}</span>
                      <span style={{ fontSize: "13px", fontWeight: 600, color: log.highlight ? "#ffb4ab" : "#dae2fd" }}>{log.title}</span>
                    </div>
                    <p style={{ fontSize: "12px", color: "#8a97b8", marginLeft: "60px" }}>{log.desc}</p>
                  </div>
              ))}
            </div>
          </div>
        </div>

        {/* Raw JSON */}
        <div style={{ background: "#131b2e", borderRadius: "24px", padding: "32px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
            <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8" }}>Raw JSON Response</span>
            <button
                onClick={() => navigator.clipboard.writeText(JSON.stringify(result, null, 2))}
                style={{ background: "transparent", border: "none", cursor: "pointer", color: "#4cd6ff", fontSize: "13px", fontWeight: 500 }}
            >
              Copy Response
            </button>
          </div>
          <pre style={{
            fontFamily: "'JetBrains Mono',monospace", fontSize: "13px",
            lineHeight: 1.8, color: "#8a97b8", overflow: "auto",
            background: "#0b1326", borderRadius: "12px", padding: "24px"
          }}>
          <code>{JSON.stringify(result, null, 2)?.replace(/"([^"]+)":/g, (_, k) => `"<span style="color:#4cd6ff">${k}</span>":`)}</code>
        </pre>
        </div>

      </div>
  );
}