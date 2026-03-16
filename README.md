# 🔐 SecureAuth - AI-Powered Authentication System

> CSE212 Cyber Security - Group 2 | Modular Authentication Framework with AI-powered security features

**University:** Ahmedabad University
**Course:** CSE212 - Cyber Security

---

## 👥 Team Modules

| Module | File | Author | Status |
|--------|------|--------|--------|
| AI Adaptive Authentication | `src/adaptive/adaptive_auth.py` | Rewant | ✅ Complete |
| Security Protection | `src/security/security_protection.py` | Rewant | ✅ Complete |
| Database Configuration | `src/database.py` | Rewant | ✅ Complete |

---

## 🚀 Features

### 🤖 Module 6: AI Adaptive Authentication
- Machine Learning (Isolation Forest algorithm) for anomaly detection
- Risk scoring system (0–100) with LOW / MEDIUM / HIGH levels
- Learns each user's normal login behavior over time
- Automatically flags suspicious logins by time, location, and device
- Recommends: Allow / Extra verification / Block

### 🔒 Module 7: Security Protection
- Brute force protection — account lockout after 5 failed attempts
- Rate limiting — max 20 requests/minute per IP
- Credential stuffing detection across multiple usernames
- Suspicious user-agent detection (bots, scripts, curl)
- Full security event logging with severity levels

---

## 🛠️ Setup & Installation

### Prerequisites
- Python 3.12+
- MariaDB / MySQL
- WSL (Ubuntu) or Linux

### 1. Clone the Repository
```bash
git clone https://github.com/Rewant1908/SecureAuth.git
cd SecureAuth
```

### 2. Install Dependencies
```bash
pip3 install numpy pandas scikit-learn pymysql --break-system-packages
```

### 3. Database Setup
```bash
# Start MariaDB
sudo service mariadb start

# Login as root
sudo mariadb
```

```sql
CREATE DATABASE secureauth_db;
CREATE USER 'secureauth_user'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON secureauth_db.* TO 'secureauth_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

```bash
# Initialize all tables automatically
python3 src/database.py
```

### 4. Run Modules
```bash
# Test AI Adaptive Authentication
python3 src/adaptive/adaptive_auth.py

# Test Security Protection
python3 src/security/security_protection.py
```

---

## 🧪 Test Results

### AI Adaptive Authentication
| Scenario | Risk Score | Risk Level | Decision |
|----------|-----------|------------|----------|
| Normal login (2 PM, same device, same location) | 20/100 | LOW | ✅ Allow |
| Suspicious (3 AM, new location) | 80/100 | HIGH | 🚫 Block |
| Very suspicious (3 AM, new location + new device) | 95/100 | HIGH | 🚫 Block |

### Security Protection
| Test | Result |
|------|--------|
| 3 failed login attempts | ✅ Not locked |
| 6 failed login attempts | 🔒 Account locked |
| Rate limiting (20 req/min) | ✅ Working |
| Credential stuffing (12 usernames) | ✅ Detected |
| Security event logging | ✅ Logged |
| Suspicious user agent (curl, python-requests) | ✅ Detected |

---

## 📁 Project Structure

```
SecureAuth/
├── src/
│   ├── adaptive/
│   │   ├── __init__.py
│   │   └── adaptive_auth.py           # AI Adaptive Auth Module
│   ├── security/
│   │   ├── __init__.py
│   │   └── security_protection.py     # Security Protection Module
│   └── database.py                    # DB Connection & Table Init
├── .gitignore
└── README.md
```

---

## 🗄️ Database Tables

| Table | Purpose |
|-------|---------|
| `users` | User accounts and credentials |
| `login_attempts` | Login history, failures, and reasons |
| `behavior_patterns` | ML-learned behavior profiles per user |
| `security_events` | Security incident logs with severity |

---

## 🤝 Contributing (Team)

```bash
# Pull latest changes before working
git pull origin main

# Add your module to src/
git add src/your_module/
git commit -m "Added [Your Name]'s [Module Name] module"
git push origin main
```

---

## 📜 License

This project is for academic purposes — CSE212 Cyber Security, Ahmedabad University, 2026.
