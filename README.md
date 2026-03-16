# 🔐 SecureAuth - AI-Powered Authentication System

## About

**SecureAuth** is an AI-powered modular authentication system built in Python with MariaDB. It uses Machine Learning (Isolation Forest algorithm) to learn each user's normal login behavior and assigns a real-time risk score (0-100) to every login attempt. Low-risk logins are allowed instantly, while suspicious logins based on unusual time, location, or device are flagged or blocked automatically. The system also includes a complete security layer with brute force protection (account lockout after 5 failed attempts), rate limiting (20 requests/minute per IP), credential stuffing detection, suspicious user-agent filtering, and full security event logging with severity levels. Built as a group project for **CSE212 Cyber Security** at **Ahmedabad University**, the system is designed to be modular so each team member's module plugs directly into the main authentication API.

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
- Risk scoring system (0-100) with LOW / MEDIUM / HIGH levels
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
sudo service mariadb start
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
python3 src/database.py
```

### 4. Run Modules
```bash
python3 src/adaptive/adaptive_auth.py
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
│   │   └── adaptive_auth.py
│   ├── security/
│   │   ├── __init__.py
│   │   └── security_protection.py
│   └── database.py
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
git pull origin main
git add src/your_module/
git commit -m "Added [Your Name]'s [Module Name] module"
git push origin main
```

---

## 📜 License

This project is for academic purposes — CSE212 Cyber Security, Ahmedabad University, 2026.
