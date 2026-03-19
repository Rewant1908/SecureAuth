# 🔐 SecureAuth - AI-Powered Authentication System

SecureAuth is a modular authentication system built in Python with MariaDB that combines JWT authentication, security protection, and AI-based risk scoring into a single login flow.

LOW risk → Allow | MEDIUM → Require MFA | HIGH → Block

---

## 👥 Team
JWT + API Integration — Daksh (Complete)  
AI Adaptive Auth — Rewant (Complete)  
Security Protection — Rewant (Complete)  
Other Modules — Team (In Progress)

---

## 🚀 Features
- Secure login with bcrypt
- JWT access & refresh tokens
- Brute-force protection (5 attempts → lock)
- Rate limiting (20 req/min/IP)
- AI risk scoring (Isolation Forest)
- Risk-based decision system

---

## ⚙️ Setup & Run
pip install -r requirements.txt

sudo service mariadb start  
sudo mysql

CREATE DATABASE secureauth_db;  
CREATE USER 'secureauth_user'@'%' IDENTIFIED BY 'SecurePass123!';  
GRANT ALL PRIVILEGES ON secureauth_db.* TO 'secureauth_user'@'%';  
FLUSH PRIVILEGES;  
EXIT;

python src/database.py  
python src/main.py

Server → http://localhost:5000

---

## 🔗 API (Login)
POST /api/login

Request:
{
"username": "admin",
"password": "admin123"
}

Response:
{
"status": "success",
"access_token": "...",
"refresh_token": "...",
"risk_score": 20
}

---

## 📁 Structure
SecureAuth/
├── src/
│   ├── adaptive/
│   ├── security/
│   ├── jwt_handler/
│   ├── database.py
│   └── main.py
├── config/
├── docs/
├── requirements.txt
└── README.md

---

## 🎯 Status
Login API working  
JWT implemented  
AI + Security integrated  
Fully functional system

---

## 📜 License
Academic project — CSE212 Cyber Security (Ahmedabad University)