# 🔐 SecureAuth - AI-Powered Authentication System

## About

**SecureAuth** is an AI-powered modular authentication system built in Python with MariaDB. It uses Machine Learning (Isolation Forest algorithm) to learn each user's normal login behavior and assigns a real-time risk score (0-100) to every login attempt. Low-risk logins are allowed instantly, while suspicious logins based on unusual time, location, or device are flagged or blocked automatically.

The system also includes a complete security layer with brute force protection (account lockout after 5 failed attempts), rate limiting (20 requests/minute per IP), credential stuffing detection, suspicious user-agent filtering, and full security event logging with severity levels. Built as a group project for **CSE212 Cyber Security** at **Ahmedabad University**, the system is designed to be modular so each team member's module plugs directly into the main authentication API.

**University:** Ahmedabad University
**Course:** CSE212 - Cyber Security

---

## 👥 Team & Modules

| Module | Folder | Author | Status |
|--------|--------|--------|--------|
| Authentication | `src/auth/` | Ansh | ⏳ In Progress |
| JWT Handler | `src/jwt_handler/` | Daksh | ⏳ In Progress |
| Multi-Factor Auth (MFA) | `src/mfa/` | Ansh | ⏳ In Progress |
| Role-Based Access Control (RBAC) | `src/rbac/` | Nandan | ⏳ In Progress |
| Session Management | `src/session/` | Nandan | ⏳ In Progress |
| AI Adaptive Authentication | `src/adaptive/` | Rewant | ✅ Complete |
| Security Protection | `src/security/` | Rewant | ✅ Complete |
| Database Configuration | `src/database.py` | Rewant | ✅ Complete |

---

## 🚀 Features

### 🔐 Authentication (`src/auth/`) — Ansh
- User registration and login
- Password hashing and verification
- Credential validation

### 🎫 JWT Handler (`src/jwt_handler/`) — Daksh
- JSON Web Token generation and validation
- Token expiry and refresh handling
- Secure token storage

### 📱 Multi-Factor Auth — MFA (`src/mfa/`) — Ansh
- OTP generation and verification
- Email/SMS-based second factor
- TOTP support

### 🛡️ Role-Based Access Control — RBAC (`src/rbac/`) — Nandan
- User roles: admin, user, guest
- Permission-based access control
- Role assignment and management

### 💾 Session Management (`src/session/`) — Nandan
- Session creation and expiry
- Active session tracking
- Session invalidation on logout

### 🤖 AI Adaptive Authentication (`src/adaptive/`) — Rewant
- Machine Learning (Isolation Forest) anomaly detection
- Risk scoring system (0-100) with LOW / MEDIUM / HIGH levels
- Learns each user's normal login behavior over time
- Flags suspicious logins by time, location, and device

### 🔒 Security Protection (`src/security/`) — Rewant
- Brute force protection — lockout after 5 failed attempts
- Rate limiting — max 20 requests/minute per IP
- Credential stuffing detection
- Suspicious user-agent detection
- Full security event logging

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
pip3 install -r requirements.txt
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

### 4. Run the Application
```bash
python3 src/main.py
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
│   ├── auth/                          # Authentication (Ansh)
│   ├── jwt_handler/                   # JWT Handler (Daksh)
│   ├── mfa/                           # Multi-Factor Auth (Ansh)
│   ├── rbac/                          # Role-Based Access Control (Nandan)
│   ├── session/                       # Session Management (Nandan)
│   ├── adaptive/                      # AI Adaptive Auth (Rewant) ✅
│   ├── security/                      # Security Protection (Rewant) ✅
│   ├── database.py                    # DB Connection & Table Init (Rewant) ✅
│   └── main.py                        # Main API entry point
├── requirements.txt
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
# Always pull latest before working
git pull origin main

# Add your module
git add src/your_module/
git commit -m "Added [Your Name]'s [Module Name] module"
git push origin main
```

> See the [Wiki](https://github.com/Rewant1908/SecureAuth/wiki) for full in-depth documentation.

---

## 📜 License

This project is for academic purposes — CSE212 Cyber Security, Ahmedabad University, 2026.
