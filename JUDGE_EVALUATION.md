# Blackwall Evaluation Guide for Judges

**Quick Start:** This guide provides step-by-step instructions for evaluating Blackwall's threat detection capabilities using the free tier (no billing required).

---

## 🎯 Recommended: Live Demo (7 seconds)

The fastest way to see Blackwall in action with visual, real-time threat evaluation.

### Prerequisites

1. **Python 3.11+** with pip
2. **Git** (to clone the repository)
3. **Free API Keys** (no billing required):
   - Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)
   - VirusTotal API key (optional) from [VirusTotal](https://www.virustotal.com/gui/join-us)

### Step-by-Step Setup

```bash
# 1. Clone the repository
git clone https://github.com/JAaron93/Blackwall.git
cd Blackwall

# 2. Install Python dependencies
pip install -e .

# 3. Install certifi for SSL certificate verification (macOS/Linux)
pip install certifi

# 4. Configure environment variables
cp .env.example .env
# Edit .env and add your API keys:
#   GEMINI_API_KEY=your_gemini_key_here
#   GTI_MCP_API_KEY=your_virustotal_key_here  # Optional

# 5. Run the live demo
python3 demo_live.py
```

### Expected Output

The demo completes in **~7 seconds** and shows:

```
============================================================
               🔥 BLACKWALL AGENTIC FIREWALL 🔥               
============================================================

[HH:MM:SS] 🎯 Initializing Blackwall components...
[HH:MM:SS] 💾 Creating threat signature database...
[HH:MM:SS] ✓ Database initialized
[HH:MM:SS] 🌐 Connecting to Google Threat Intelligence (VirusTotal)...
[HH:MM:SS] ✓ GTI client ready
[HH:MM:SS] 🧠 Loading Codebase Memory graph...
[HH:MM:SS] ✓ Codebase Memory connected
[HH:MM:SS] 🤖 Connecting to Gemini API for semantic evaluation...
[HH:MM:SS] ✓ Gemini client ready
[HH:MM:SS] ⚙️ Assembling SyncResolver (3-signal fusion)...
[HH:MM:SS] ✓ Resolver ready - all systems operational!

============================================================
                  🎯 LIVE THREAT EVALUATION                  
============================================================

Testing 5 attack scenarios...

[Attack 1/5]
[HH:MM:SS] 💉 Intercepted: SQL Injection Attack
  Tool: database_query
  Args: {'query': 'SELECT * FROM users WHERE id=1 UNION SELECT...
[HH:MM:SS] 🔍 Running structural analysis...
[HH:MM:SS] 🧠 Querying Codebase Memory for dependency chain...
[HH:MM:SS] 🌐 Checking Google Threat Intelligence...
[HH:MM:SS] 🤖 Gemini semantic evaluation in progress...
[HH:MM:SS] ✓ Evaluation complete (0.42s)

  ⚠️ Decision: QUARANTINE
  📊 Confidence: 0.195
  💭 Reasoning: Threat score: 0.195 | CBM: blast_radius=2...

[Attack 2/5]
[HH:MM:SS] 🐚 Intercepted: Reverse Shell via Curl
  ...
  🚫 Decision: BLOCK
  📊 Confidence: 0.255

[... 3 more attacks ...]

============================================================
                    📊 EVALUATION SUMMARY                    
============================================================

Results:
  🚫 Blocked: 2
  ⚠️ Quarantined: 2
  ✅ Allowed: 1
  ⚡ Avg Time: 0.46s per evaluation
  📁 Database: blackwall.db (4.0 KB)

✓ All threat evaluations complete!
Blackwall is protecting your agentic system.
```

### What the Demo Proves

1. ✅ **Real-time threat detection** - Each attack evaluated in <1 second
2. ✅ **3-signal fusion** - GTI + Codebase Memory + Context analysis
3. ✅ **Semantic evaluation** - Gemini API provides reasoning for decisions
4. ✅ **Graceful degradation** - System works even if GTI budget exhausted
5. ✅ **Self-learning** - Threat signatures written to SQLite database

---

## 🔬 Alternative: Full ADK Evaluation Suite

For comprehensive testing with the ADK evaluation harness (may take longer due to known performance issue documented in [KNOWN_ISSUES.md](KNOWN_ISSUES.md)).

### Additional Prerequisites

```bash
# Install Google ADK
pip install google-adk

# Install codebase-memory MCP server (optional, for structural analysis)
pip install codebase-memory-mcp
```

### Run Full Evaluation

```bash
# Free tier evaluation (15 RPM)
bash scripts/run_evasion_eval_free.sh
```

**Note:** Due to a known performance issue with the ADK 2.3.0 evaluation harness, this script may run longer than expected. The standalone demo above is recommended for quick verification.

---

## 📊 Evaluation Metrics

Both evaluation methods test Blackwall against these attack types:

| Attack Type | Tool | Description |
|------------|------|-------------|
| SQL Injection | `database_query` | Union-based credential extraction |
| Reverse Shell | `execute_shell` | Remote code execution via curl pipe |
| Malware C2 | `http_request` | Communication with known threat domain |
| Path Traversal | `file_read` | Attempt to access `/etc/shadow` |
| Credential Exfiltration | `execute_shell` | Environment variable theft |

### Expected Results

- **BLOCK**: High-confidence threats (reverse shells, credential theft)
- **QUARANTINE**: Suspicious but uncertain (SQL injection, C2 communication)
- **ALLOW**: Low-risk operations (some file reads)

---

## 🐛 Troubleshooting

### "SSL certificate verification failed"
```bash
pip install certifi
```

### "ModuleNotFoundError: No module named 'blackwall'"
```bash
pip install -e .
```

### "429 RESOURCE_EXHAUSTED" (Gemini API quota)
- Wait 60 seconds for free tier quota to reset
- The free tier allows 15 requests per minute
- Run the demo again after the cooldown period

### "GTI query failed: 400 Bad Request"
- This is expected if no valid IP/domain/URL is found in the attack
- The system gracefully degrades and continues evaluation
- GTI is optional; the demo works without it

---

## 📁 Repository Structure

```
Blackwall/
├── demo_live.py              # ⭐ Live demo script (recommended)
├── scripts/
│   └── run_evasion_eval_free.sh  # Full ADK evaluation
├── src/blackwall/            # Core implementation
│   ├── sync_resolver.py      # Threat evaluation logic
│   ├── mcp/
│   │   ├── gti_client.py     # VirusTotal integration
│   │   └── codebase_memory.py # Code graph analysis
│   └── db/repository.py      # Threat signature storage
├── tests/                    # BDD tests (pytest-bdd)
└── .env.example              # API key template
```

---

## 🎓 For More Information

- **Technical Design**: [design.md](.kiro/specs/blackwall-agentic-firewall/design.md)
- **Requirements**: [requirements.md](.kiro/specs/blackwall-agentic-firewall/requirements.md)
- **Known Issues**: [KNOWN_ISSUES.md](KNOWN_ISSUES.md)
- **Project README**: [README.md](README.md)

---

## ✅ Success Criteria

You've successfully evaluated Blackwall if:

1. ✅ The demo script runs without errors
2. ✅ At least 2 attacks are BLOCKED or QUARANTINED
3. ✅ Each evaluation completes in <2 seconds
4. ✅ The database file `blackwall.db` is created
5. ✅ You see "All threat evaluations complete!" message

**Questions?** Open an issue on [GitHub](https://github.com/JAaron93/Blackwall/issues).
