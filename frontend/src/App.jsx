import { useState } from "react";

const API = "http://localhost:5000";

async function apiFetch(path, options = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  const data = await res.json();
  return { ok: res.ok, status: res.status, data };
}

function PasswordInput({ password, setPassword, onEnter }) {
  const [showPassword, setShowPassword] = useState(false);

  return (
      <div style={{ display: "flex", alignItems: "center", gap: "12px", background: "#1e2840", borderRadius: "10px", padding: "0 16px" }}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4a5580" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <input value={password} onChange={e => setPassword(e.target.value)} type={showPassword ? "text" : "password"} placeholder="••••••••••••" onKeyDown={e => e.key === "Enter" && onEnter()} style={{ flex: 1, padding: "14px 0", background: "transparent", border: "none", outline: "none", color: "#dae2fd", fontSize: "15px" }} />
        <button type="button" onClick={() => setShowPassword(!showPassword)} style={{ background: "none", border: "none", cursor: "pointer", padding: "0", display: "flex", alignItems: "center", justifyContent: "center" }}>
          {showPassword ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4cd6ff" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4a5580" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          )}
        </button>
      </div>
  );
}

export default function App() {
  const [page, setPage] = useState("simulator");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState("");
  const [mfaMethod, setMfaMethod] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);
  const [mfaError, setMfaError] = useState("");
  const [session, setSession] = useState(null);

  const scenarios = {
    normal:     { username: "john.doe",         password: "SecurePass123!", location_changed: false, device_changed: false, unusual_hour: false },
    suspicious: { username: "admin",            password: "password123",    location_changed: true,  device_changed: false, unusual_hour: true },
    attack:     { username: "'; DROP TABLE;--", password: "hacker",         location_changed: true,  device_changed: true,  unusual_hour: true },
  };

  const handleScenario = (type) => {
    setUsername(scenarios[type].username);
    setPassword(scenarios[type].password);
    setError("");
  };

  const handleAnalyze = async () => {
    if (!username || !password) { setError("Username and password are required."); return; }
    setLoading(true);
    setError("");

    const scenarioKey = Object.keys(scenarios).find(key => scenarios[key].username === username);
    const scenarioData = scenarioKey ? scenarios[scenarioKey] : { location_changed: false, device_changed: false, unusual_hour: false };

    const loginPayload = {
      username,
      password,
      location_changed: scenarioData.location_changed,
      device_changed: scenarioData.device_changed,
      unusual_hour: scenarioData.unusual_hour,
      hours_since_last: 24,
    };

    const { ok, status, data } = await apiFetch("/api/login", {
      method: "POST",
      body: JSON.stringify(loginPayload),
    });

    setLoading(false);

    if (status === 200 && data.mfa_required) {
      setMfaToken(data.mfa_token);
      setMfaMethod(data.mfa_method);
      setMfaRequired(true);
      setResult({ status: "mfa_required", mfa_method: data.mfa_method, risk_score: data.risk_score, risk_level: data.risk_level, otp_sent: data.otp_sent, delivery_message: data.delivery_message });
      setPage("dashboard");
      return;
    }

    if (!ok) {
      setError(data.error || "Login failed.");
      setResult({ status: "blocked", error: data.error, risk_score: data.risk_score, risk_level: data.risk_level });
      setPage("dashboard");
      return;
    }

    setSession({ access_token: data.access_token, refresh_token: data.refresh_token, session_id: data.session_id, roles: data.roles });
    setResult({ status: "success", risk_score: data.risk_score, risk_level: data.risk_level, roles: data.roles, session_id: data.session_id, message: data.message });
    setPage("dashboard");
  };

  const handleMfaVerify = async () => {
    if (!mfaCode) { setMfaError("Enter the code."); return; }
    setMfaLoading(true);
    setMfaError("");

    const endpoint = mfaMethod === "totp" ? "/api/mfa/totp/verify" : "/api/mfa/verify";
    const { ok, data } = await apiFetch(endpoint, {
      method: "POST",
      body: JSON.stringify({ mfa_token: mfaToken, code: mfaCode }),
    });

    setMfaLoading(false);
    if (!ok) { setMfaError(data.error || "Invalid code."); return; }

    setSession({ access_token: data.access_token, refresh_token: data.refresh_token, session_id: data.session_id, roles: data.roles });
    setMfaRequired(false);
    setResult(prev => ({ ...prev, status: "success", message: data.message, roles: data.roles }));
  };

  const handleLogout = async () => {
    if (session?.refresh_token) {
      await apiFetch("/api/logout", {
        method: "POST",
        body: JSON.stringify({ refresh_token: session.refresh_token }),
      });
    }
    setSession(null);
    setResult(null);
    setMfaRequired(false);
    setMfaCode("");
    setMfaToken("");
    setUsername("");
    setPassword("");
    setPage("simulator");
  };

  return (
      <div style={{ minHeight: "100vh", background: "#0b1326", color: "#dae2fd", fontFamily: "'Inter', sans-serif" }}>
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, height: "56px", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 40px", background: "rgba(11,19,38,0.75)", backdropFilter: "blur(20px)", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
          <span style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 800, fontSize: "18px" }}>SecureAuth</span>
          <div style={{ display: "flex", gap: "32px", fontSize: "14px" }}>
            {["simulator","dashboard"].map(p => (
                <span key={p} onClick={() => setPage(p)} style={{ cursor: "pointer", color: page === p ? "#4cd6ff" : "#8a97b8", fontWeight: page === p ? 600 : 400, transition: "color 0.2s" }}>
              {p === "simulator" ? "Login Simulator" : "Result Dashboard"}
            </span>
            ))}
          </div>
          <div onClick={session ? handleLogout : undefined} style={{ background: session ? "linear-gradient(135deg,#4cd6ff,#009dc1)" : "#1e2840", color: session ? "#001f2a" : "#8a97b8", padding: "5px 14px", borderRadius: "999px", fontSize: "11px", fontWeight: 800, letterSpacing: "0.06em", cursor: session ? "pointer" : "default" }}>
            {session ? "LOGOUT" : "PROTECTED"}
          </div>
        </div>
        <div style={{ position: "fixed", top: 0, left: 0, bottom: 0, width: "240px", zIndex: 50, background: "#131b2e", display: "flex", flexDirection: "column", padding: "80px 20px 32px" }}>
          <div style={{ marginBottom: "36px" }}>
            <div style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 800, fontSize: "16px" }}>SecureAuth</div>
            <div style={{ fontSize: "10px", fontWeight: 600, letterSpacing: "0.12em", color: "#4cd6ff", marginTop: "4px" }}>AI SENTINEL ACTIVE</div>
          </div>
          <nav style={{ display: "flex", flexDirection: "column", gap: "4px", flex: 1 }}>
            <NavItem icon="fingerprint" label="Login Simulator"  active={page==="simulator"} onClick={() => setPage("simulator")} />
            <NavItem icon="dashboard"   label="Result Dashboard" active={page==="dashboard"} onClick={() => setPage("dashboard")} />
          </nav>
          <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: "20px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <div style={{ width: "32px", height: "32px", borderRadius: "50%", background: "#2d3449", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8a97b8" strokeWidth="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
              </div>
              <div>
                <div style={{ fontSize: "13px", fontWeight: 600 }}>{session?.roles?.[0] ?? "System Operator"}</div>
                <div style={{ fontSize: "11px", color: "#8a97b8" }}>{session ? "Authenticated" : "Root Access"}</div>
              </div>
            </div>
          </div>
        </div>
        <div style={{ marginLeft: "240px", paddingTop: "56px", minHeight: "100vh" }}>
          {page === "simulator"
              ? <SimulatorPage username={username} password={password} loading={loading} error={error} setUsername={setUsername} setPassword={setPassword} onAnalyze={handleAnalyze} onScenario={handleScenario} />
              : <DashboardPage result={result} mfaRequired={mfaRequired} mfaMethod={mfaMethod} mfaCode={mfaCode} setMfaCode={setMfaCode} mfaLoading={mfaLoading} mfaError={mfaError} onMfaVerify={handleMfaVerify} session={session} />
          }
        </div>
      </div>
  );
}

function NavItem({ icon, label, active, onClick }) {
  const icons = {
    fingerprint: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22C6 22 2 17.5 2 12S6 2 12 2s10 4.5 10 10"/><path d="M12 18c-2.5 0-4-2-4-4s1.5-4 4-4 4 2 4 4"/></svg>,
    dashboard:   <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>,
  };
  return (
      <div onClick={onClick} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "10px 12px", borderRadius: "10px", cursor: "pointer", background: active ? "rgba(76,214,255,0.1)" : "transparent", color: active ? "#4cd6ff" : "#8a97b8", fontSize: "14px", fontWeight: active ? 600 : 400, transition: "all 0.2s", marginBottom: "2px" }}
           onMouseEnter={e => { if (!active) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
           onMouseLeave={e => { if (!active) e.currentTarget.style.background = "transparent"; }}>
        {icons[icon]}{label}
      </div>
  );
}

function SimulatorPage({ username, password, loading, error, setUsername, setPassword, onAnalyze, onScenario }) {
  return (
      <div style={{ padding: "56px 64px", maxWidth: "900px" }}>
        <div style={{ marginBottom: "48px" }}>
          <h1 style={{ fontFamily: "'Manrope',sans-serif", fontSize: "52px", fontWeight: 800, lineHeight: 1.1, marginBottom: "16px" }}>Simulate Access</h1>
          <p style={{ fontSize: "16px", color: "#8a97b8", lineHeight: 1.6, maxWidth: "480px" }}>Run AI-driven behavioral analysis on authentication attempts to detect anomaly patterns.</p>
        </div>
        <div style={{ background: "#171f33", borderRadius: "24px", padding: "40px", maxWidth: "520px", marginBottom: "32px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
          <div style={{ marginBottom: "20px" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "8px" }}>Username</div>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", background: "#1e2840", borderRadius: "10px", padding: "0 16px" }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4a5580" strokeWidth="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
              <input value={username} onChange={e => setUsername(e.target.value)} placeholder="e.g. sentinel_operator" style={{ flex: 1, padding: "14px 0", background: "transparent", border: "none", outline: "none", color: "#dae2fd", fontSize: "15px" }} />
            </div>
          </div>
          <div style={{ marginBottom: "28px" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "8px" }}>Password</div>
            <PasswordInput password={password} setPassword={setPassword} onEnter={onAnalyze} />
          </div>
          {error && (<div style={{ marginBottom: "16px", padding: "12px 16px", background: "rgba(255,180,171,0.1)", border: "1px solid rgba(255,180,171,0.25)", borderRadius: "8px", fontSize: "13px", color: "#ffb4ab" }}>{error}</div>)}
          <button onClick={onAnalyze} disabled={loading} style={{ width: "100%", padding: "16px", background: loading ? "#1e2840" : "linear-gradient(135deg,#4cd6ff,#009dc1)", border: "none", borderRadius: "10px", color: loading ? "#8a97b8" : "#001f2a", fontFamily: "'Manrope',sans-serif", fontSize: "15px", fontWeight: 700, cursor: loading ? "not-allowed" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: "8px", boxShadow: loading ? "none" : "0 0 24px rgba(76,214,255,0.2)", transition: "all 0.15s" }} onMouseDown={e => { if (!loading) e.currentTarget.style.transform = "scale(0.98)"; }} onMouseUp={e => { e.currentTarget.style.transform = "scale(1)"; }}>
            {loading ? <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ animation: "spin 1s linear infinite" }}><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>Analyzing...</> : <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Analyze Login</>}
          </button>
        </div>
        <div style={{ background: "#131b2e", borderRadius: "16px", padding: "28px", maxWidth: "520px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
            <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8" }}>Demo Scenarios</span>
            <span style={{ fontSize: "11px", color: "#4a5580", letterSpacing: "0.06em", textTransform: "uppercase" }}>Select Preset</span>
          </div>
          <div style={{ display: "flex", gap: "12px" }}>
            <ScenarioBtn label="Normal" color="#4cffb0" onClick={() => onScenario("normal")} />
            <ScenarioBtn label="Suspicious" color="#ffc04c" onClick={() => onScenario("suspicious")} />
            <ScenarioBtn label="Attack" color="#ffb4ab" onClick={() => onScenario("attack")} />
          </div>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
  );
}

function ScenarioBtn({ label, color, onClick }) {
  const icons = {
    Normal: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>,
    Suspicious: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    Attack: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>,
  };
  return (
      <div onClick={onClick} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "10px", padding: "20px 12px", background: "#171f33", borderRadius: "12px", cursor: "pointer", border: "1px solid transparent", transition: "all 0.2s" }}
           onMouseEnter={e => { e.currentTarget.style.background="#1e2840"; e.currentTarget.style.borderColor=`${color}33`; e.currentTarget.style.transform="translateY(-2px)"; }}
           onMouseLeave={e => { e.currentTarget.style.background="#171f33"; e.currentTarget.style.borderColor="transparent"; e.currentTarget.style.transform="translateY(0)"; }}>
        {icons[label]}
        <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "#8a97b8" }}>{label}</span>
      </div>
  );
}

function DashboardPage({ result, mfaRequired, mfaMethod, mfaCode, setMfaCode, mfaLoading, mfaError, onMfaVerify, session }) {
  const score = result?.risk_score ?? 0;
  const level = (result?.risk_level ?? "LOW").toUpperCase();
  const ringColor = level === "HIGH" ? "#ffb4ab" : level === "MEDIUM" ? "#ffc04c" : "#4cffb0";
  const circumference = 2 * Math.PI * 52;
  const dashOffset = circumference - (score / 100) * circumference;

  if (!result) return (<div style={{ padding: "80px 48px", color: "#8a97b8", fontSize: "15px" }}>No results yet. Run a login simulation first.</div>);

  const decisionColor = result.status === "success" ? "#4cffb0" : result.status === "blocked" ? "#ffb4ab" : "#ffc04c";
  const decisionLabel = result.status === "success" ? "ACCESS GRANTED" : result.status === "blocked" ? "ACCESS BLOCKED" : "MFA REQUIRED";
  const decisionDesc = result.status === "success" ? "Authentication successful. Session tokens issued." : result.status === "blocked" ? (result.error || "High risk login blocked by AI Sentinel.") : "AI Sentinel detected unusual patterns. Secondary verification required.";

  return (
      <div style={{ padding: "40px 48px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "20px", marginBottom: "24px" }}>
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "36px", display: "flex", flexDirection: "column", alignItems: "center", gap: "16px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <svg width="140" height="140" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="52" fill="none" stroke="#1e2840" strokeWidth="10"/>
              <circle cx="60" cy="60" r="52" fill="none" stroke={ringColor} strokeWidth="10" strokeDasharray={circumference} strokeDashoffset={dashOffset} strokeLinecap="round" transform="rotate(-90 60 60)" style={{ transition: "stroke-dashoffset 1s ease" }}/>
              <text x="60" y="56" textAnchor="middle" fill="#dae2fd" fontSize="26" fontWeight="800" fontFamily="Manrope,sans-serif">{Math.round(score)}</text>
              <text x="60" y="72" textAnchor="middle" fill="#8a97b8" fontSize="9" fontFamily="Inter,sans-serif" letterSpacing="1">RISK SCORE</text>
            </svg>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: ringColor }}/>
              <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: ringColor }}>{level} RISK DETECTED</span>
            </div>
          </div>
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "36px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "20px" }}>Security Decision</div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", background: `${decisionColor}18`, border: `1px solid ${decisionColor}40`, borderRadius: "10px", padding: "14px 18px", marginBottom: "20px" }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={decisionColor} strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <span style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 700, fontSize: "14px", color: decisionColor, letterSpacing: "0.06em" }}>{decisionLabel}</span>
            </div>
            <p style={{ fontSize: "13px", color: "#8a97b8", lineHeight: 1.7 }}>{decisionDesc}</p>
            {mfaRequired && (
                <div style={{ marginTop: "20px" }}>
                  <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "8px" }}>Enter {mfaMethod?.toUpperCase()} Code</div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <input value={mfaCode} onChange={e => setMfaCode(e.target.value)} onKeyDown={e => e.key === "Enter" && onMfaVerify()} placeholder="000000" maxLength={6} style={{ flex: 1, padding: "10px 14px", background: "#1e2840", border: "1px solid rgba(76,214,255,0.2)", borderRadius: "8px", color: "#dae2fd", fontSize: "18px", fontFamily: "'JetBrains Mono',monospace", letterSpacing: "0.2em", outline: "none", textAlign: "center" }} />
                    <button onClick={onMfaVerify} disabled={mfaLoading} style={{ padding: "10px 16px", background: "linear-gradient(135deg,#4cd6ff,#009dc1)", border: "none", borderRadius: "8px", color: "#001f2a", fontWeight: 700, fontSize: "13px", cursor: mfaLoading ? "not-allowed" : "pointer" }}>{mfaLoading ? "..." : "Verify"}</button>
                  </div>
                  {mfaError && <div style={{ marginTop: "8px", fontSize: "12px", color: "#ffb4ab" }}>{mfaError}</div>}
                </div>
            )}
          </div>
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "36px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8", marginBottom: "20px" }}>Threat Level</div>
            <div style={{ display: "flex", alignItems: "baseline", gap: "10px", marginBottom: "24px" }}>
              <span style={{ fontFamily: "'Manrope',sans-serif", fontSize: "40px", fontWeight: 800, color: ringColor }}>{level === "HIGH" ? "Critical" : level === "MEDIUM" ? "Elevated" : "Normal"}</span>
              <span style={{ fontSize: "13px", color: "#8a97b8" }}>Zone {level === "HIGH" ? "A" : level === "MEDIUM" ? "B" : "C"}</span>
            </div>
            <div style={{ background: "#1e2840", borderRadius: "4px", height: "6px", overflow: "hidden" }}>
              <div style={{ width: `${score}%`, height: "100%", background: `linear-gradient(to right, ${ringColor}88, ${ringColor})`, borderRadius: "4px", transition: "width 1s ease" }}/>
            </div>
            {session && (<div style={{ marginTop: "16px", fontSize: "11px", color: "#4cd6ff", fontFamily: "'JetBrains Mono',monospace" }}>SESSION ACTIVE</div>)}
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "24px" }}>
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "32px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "28px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4cd6ff" strokeWidth="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                <span style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 700, fontSize: "16px" }}>Session Details</span>
              </div>
              <span style={{ background: "rgba(76,214,255,0.1)", border: "1px solid rgba(76,214,255,0.25)", color: "#4cd6ff", padding: "3px 10px", borderRadius: "4px", fontSize: "11px", fontFamily: "'JetBrains Mono',monospace" }}>{session ? "LIVE" : "PENDING"}</span>
            </div>
            {[
              { label: "MFA Method", value: result.mfa_method?.toUpperCase() || (session ? "NONE" : "—"), accent: false },
              { label: "Session ID", value: session?.session_id ? session.session_id.slice(0,20)+"..." : "—", accent: true },
              { label: "Roles", value: session?.roles?.join(", ") || "—", accent: false },
              { label: "Risk Score", value: `${Math.round(score)} / 100`, accent: false },
            ].map((row, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 0", borderBottom: i < 3 ? "1px solid rgba(255,255,255,0.04)" : "none" }}>
                  <span style={{ fontSize: "13px", color: "#8a97b8" }}>{row.label}</span>
                  <span style={{ fontSize: "13px", fontWeight: 500, color: row.accent ? "#4cd6ff" : "#dae2fd", fontFamily: row.accent ? "'JetBrains Mono',monospace" : "inherit" }}>{row.value}</span>
                </div>
            ))}
          </div>
          <div style={{ background: "#171f33", borderRadius: "24px", padding: "32px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "28px" }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4cd6ff" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              <span style={{ fontFamily: "'Manrope',sans-serif", fontWeight: 700, fontSize: "16px" }}>Security Logs</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              {[
                { time: new Date().toLocaleTimeString(), title: result.status === "blocked" ? "Login Blocked" : result.status === "mfa_required" ? "MFA Triggered" : "Login Successful", desc: result.error || result.message || result.delivery_message || "Event recorded.", highlight: result.status === "blocked" },
                { time: new Date(Date.now()-1000).toLocaleTimeString(), title: "Risk Assessment", desc: `Score: ${Math.round(score)} — Level: ${level}`, highlight: level === "HIGH" },
                { time: new Date(Date.now()-2000).toLocaleTimeString(), title: "AI Sentinel Scan", desc: "Behavioral analysis complete.", highlight: false },
              ].map((log, i) => (
                  <div key={i} style={{ padding: "14px 16px", borderRadius: "10px", background: log.highlight ? "rgba(255,180,171,0.08)" : "transparent", border: log.highlight ? "1px solid rgba(255,180,171,0.15)" : "1px solid transparent" }}>
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
        <div style={{ background: "#131b2e", borderRadius: "24px", padding: "32px", boxShadow: "12px 24px 48px rgba(218,226,253,0.06)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
            <span style={{ fontSize: "11px", fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "#8a97b8" }}>Raw API Response</span>
            <button onClick={() => navigator.clipboard.writeText(JSON.stringify(result, null, 2))} style={{ background: "transparent", border: "none", cursor: "pointer", color: "#4cd6ff", fontSize: "13px", fontWeight: 500 }}>Copy Response</button>
          </div>
          <pre style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "13px", lineHeight: 1.8, color: "#8a97b8", overflow: "auto", background: "#0b1326", borderRadius: "12px", padding: "24px" }}>{JSON.stringify(result, null, 2)}</pre>
        </div>
      </div>
  );
}