import './index.css'
function App() {
  return (
      <div className="min-h-screen bg-[#0b1326] text-white font-sans">

        {/* NAVBAR */}
        <div className="fixed top-0 w-full bg-[#0b1326]/60 backdrop-blur-xl px-8 py-4 flex justify-between items-center z-50 border-b border-white/5">
          <h1 className="text-2xl font-bold tracking-tight">SecureAuth</h1>

          <div className="hidden md:flex gap-8 text-sm">
            <span className="text-cyan-400 font-semibold">Login Simulator</span>
            <span className="text-gray-400">Result Dashboard</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="bg-cyan-500 px-4 py-1.5 rounded-full text-xs font-bold tracking-wide">
              Protected
            </div>
          </div>
        </div>

        {/* SIDEBAR */}
        <div className="fixed top-0 left-0 h-full w-64 bg-[#111a2f]/90 backdrop-blur-lg pt-24 p-6 hidden md:flex flex-col border-r border-white/5">

          <div className="mb-8">
            <h2 className="text-lg font-bold">SecureAuth</h2>
            <p className="text-xs text-cyan-400 tracking-widest mt-1">
              AI SENTINEL ACTIVE
            </p>
          </div>

          <div className="space-y-2 text-sm">
            <div className="bg-cyan-500/10 text-cyan-400 px-4 py-3 rounded-lg">
              Login Simulator
            </div>
            <div className="text-gray-400 px-4 py-3 hover:bg-white/5 rounded-lg transition">
              Result Dashboard
            </div>
          </div>
        </div>

        {/* MAIN LAYOUT */}
        <div className="md:ml-64 pt-28 px-6 flex gap-10">

          {/* LEFT CONTENT */}
          <div className="max-w-xl w-full">

            {/* TITLE */}
            <h1 className="text-5xl font-extrabold tracking-tight mb-2">
              Simulate Access
            </h1>
            <p className="text-gray-400 mb-10 text-lg">
              Run AI-driven behavioral analysis on authentication attempts
            </p>

            {/* FORM */}
            <div className="bg-[#171f33] p-8 rounded-xl shadow-xl border border-white/5">

              <input
                  placeholder="Username"
                  className="w-full p-4 mb-4 rounded-lg bg-[#131b2e] focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
              />

              <input
                  type="password"
                  placeholder="Password"
                  className="w-full p-4 mb-4 rounded-lg bg-[#131b2e] focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
              />

              <button className="w-full bg-gradient-to-r from-cyan-400 to-blue-500 py-4 rounded-lg font-bold shadow-lg hover:scale-[1.02] transition">
                Analyze Login
              </button>
            </div>

            {/* DEMO SCENARIOS */}
            <div className="mt-8 bg-[#111a2f] p-6 rounded-xl border border-white/5">

              <h2 className="text-xs uppercase tracking-widest text-gray-400 mb-4">
                Demo Scenarios
              </h2>

              <div className="grid grid-cols-3 gap-4">

                <button className="bg-green-500/10 border border-green-500/20 text-green-400 p-4 rounded-lg flex flex-col items-center gap-2 hover:scale-105 transition">
                  <span>✔</span>
                  <span className="text-xs font-bold">Normal</span>
                </button>

                <button className="bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 p-4 rounded-lg flex flex-col items-center gap-2 hover:scale-105 transition">
                  <span>⚠</span>
                  <span className="text-xs font-bold">Suspicious</span>
                </button>

                <button className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-lg flex flex-col items-center gap-2 hover:scale-105 transition">
                  <span>⛔</span>
                  <span className="text-xs font-bold">Attack</span>
                </button>

              </div>
            </div>
          </div>

          {/* RIGHT PANEL */}
          <div className="hidden lg:block w-80">

            <div className="bg-[#171f33]/70 backdrop-blur-xl border border-white/10 rounded-xl p-6 shadow-2xl">

              <div className="text-xs uppercase text-cyan-400 tracking-widest mb-4">
                Threat Context
              </div>

              <div className="space-y-5">

                <div className="flex gap-3 items-center">
                  <div className="w-10 h-10 bg-[#0b1326] flex items-center justify-center rounded-lg">
                    🌍
                  </div>
                  <div>
                    <div className="text-sm font-bold">Global Origin</div>
                    <div className="text-xs text-gray-400">
                      Detected from 42 regions
                    </div>
                  </div>
                </div>

                <div className="flex gap-3 items-center">
                  <div className="w-10 h-10 bg-[#0b1326] flex items-center justify-center rounded-lg">
                    ⚡
                  </div>
                  <div>
                    <div className="text-sm font-bold">Analysis Speed</div>
                    <div className="text-xs text-gray-400">
                      0.04s latency
                    </div>
                  </div>
                </div>

              </div>

            </div>
          </div>

        </div>
      </div>
  );
}

export default App;