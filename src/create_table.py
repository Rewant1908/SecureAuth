import pymysql

conn = pymysql.connect(
    host='localhost',
    user='secureauth_user',
    password='SecurePass123!',
    database='secureauth_db'
)
cursor = conn.cursor()

sql = """
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    ip_address VARCHAR(50),
    attempt_count INT DEFAULT 1,
    last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
    locked_until DATETIME NULL,
    INDEX idx_username (username),
    INDEX idx_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

cursor.execute(sql)
conn.commit()
print("Table created")
conn.close()