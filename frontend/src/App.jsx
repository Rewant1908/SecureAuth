export default function App() {
  return (
      <div style={{
        minHeight: "100vh",
        background: "#0b1326",
        color: "white",
        fontFamily: "Inter, sans-serif"
      }}>

        {/* NAVBAR */}
        <div style={{
          position: "fixed",
          top: 0,
          width: "100%",
          padding: "16px 40px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "rgba(11,19,38,0.7)",
          backdropFilter: "blur(10px)",
          borderBottom: "1px solid rgba(255,255,255,0.05)"
        }}>
          <h1 style={{fontSize: "22px", fontWeight: "bold"}}>SecureAuth</h1>

          <div style={{display: "flex", gap: "20px", fontSize: "14px"}}>
            <span style={{color: "#22d3ee"}}>Login Simulator</span>
            <span style={{color: "#9ca3af"}}>Result Dashboard</span>
          </div>

          <div style={{
            background: "#22d3ee",
            padding: "6px 12px",
            borderRadius: "999px",
            fontSize: "12px",
            fontWeight: "bold"
          }}>
            Protected
          </div>
        </div>

        {/* SIDEBAR */}
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "250px",
          height: "100%",
          background: "#111a2f",
          padding: "100px 20px"
        }}>
          <h2>SecureAuth</h2>
          <p style={{color: "#22d3ee", fontSize: "12px"}}>AI SENTINEL ACTIVE</p>

          <div style={{marginTop: "30px"}}>
            <div style={{color: "#22d3ee", marginBottom: "10px"}}>Login Simulator</div>
            <div style={{color: "#aaa"}}>Result Dashboard</div>
          </div>
        </div>

        {/* MAIN */}
        <div style={{marginLeft: "260px", paddingTop: "120px", padding: "40px"}}>

          <h1 style={{fontSize: "48px", fontWeight: "bold"}}>Simulate Access</h1>
          <p style={{color: "#9ca3af", marginBottom: "40px"}}>
            Run AI-driven behavioral analysis on authentication attempts
          </p>

          {/* CARD */}
          <div style={{
            background: "#171f33",
            padding: "30px",
            borderRadius: "12px",
            maxWidth: "400px"
          }}>
            <input placeholder="Username" style={{
              width: "100%", padding: "12px", marginBottom: "10px",
              background: "#131b2e", border: "none", color: "white"
            }} />

            <input placeholder="Password" type="password" style={{
              width: "100%", padding: "12px", marginBottom: "10px",
              background: "#131b2e", border: "none", color: "white"
            }} />

            <button style={{
              width: "100%",
              padding: "14px",
              background: "linear-gradient(to right, #22d3ee, #3b82f6)",
              border: "none",
              borderRadius: "8px",
              fontWeight: "bold"
            }}>
              Analyze Login
            </button>
          </div>

          {/* DEMO */}
          <div style={{
            marginTop: "30px",
            background: "#111a2f",
            padding: "20px",
            borderRadius: "10px",
            maxWidth: "400px"
          }}>
            <p>Demo Scenarios</p>

            <div style={{display: "flex", gap: "10px", marginTop: "10px"}}>
              <button style={{background: "#10b98133", color: "#10b981", padding: "10px"}}>Normal</button>
              <button style={{background: "#f59e0b33", color: "#f59e0b", padding: "10px"}}>Suspicious</button>
              <button style={{background: "#ef444433", color: "#ef4444", padding: "10px"}}>Attack</button>
            </div>
          </div>

        </div>
      </div>
  );
}