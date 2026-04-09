import pymysql

conn = pymysql.connect(
    host='localhost',
    user='secureauth_user',
    password='SecurePass123!',
    database='secureauth_db'
)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN last_login DATETIME NULL")
    conn.commit()
    print("Column added")
except pymysql.Error as e:
    if "Duplicate column" in str(e):
        print("Column already exists")
    else:
        print(f"Error: {e}")

conn.close()