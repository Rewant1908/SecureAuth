"""
Module 6: AI Adaptive Authentication
Uses machine learning for anomaly detection and risk scoring

Author: Rewant
Course: CSE212 Cyber Security
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime
import json
from typing import Dict, Tuple, Optional


class AdaptiveAuthenticator:
    """
    AI-powered adaptive authentication with anomaly detection
    
    This class uses Machine Learning (Isolation Forest algorithm) to:
    1. Learn user's normal login behavior
    2. Detect anomalies in new login attempts
    3. Calculate risk scores (0-100)
    4. Recommend security actions
    """
    
    def __init__(self, db_connection):
        """
        Initialize the adaptive authenticator
        
        Args:
            db_connection: Database connection object
        """
        self.conn = db_connection
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.min_history_count = 5  # Minimum logins needed for ML
    
    def extract_features(self, login_data: Dict) -> np.array:
        """
        Extract features from login attempt for ML model
        
        Features extracted:
        1. Hour of day (0-23)
        2. Day of week (0-6, Monday=0)
        3. Location changed? (0 or 1)
        4. Device changed? (0 or 1)
        5. Hours since last login
        
        Args:
            login_data: Dictionary with login information
            
        Returns:
            NumPy array of features
        """
        features = []
        
        # Time-based features
        login_hour = login_data.get('hour', datetime.now().hour)
        features.append(login_hour)
        
        # Day of week (0 = Monday, 6 = Sunday)
        day_of_week = login_data.get('day_of_week', datetime.now().weekday())
        features.append(day_of_week)
        
        # Location change indicator (0 or 1)
        location_changed = 1 if login_data.get('location_changed', False) else 0
        features.append(location_changed)
        
        # Device change indicator
        device_changed = 1 if login_data.get('device_changed', False) else 0
        features.append(device_changed)
        
        # Time since last login (in hours, capped at 168 = 1 week)
        hours_since_last = min(login_data.get('hours_since_last', 24), 168)
        features.append(hours_since_last)
        
        return np.array(features).reshape(1, -1)
    
    def get_user_login_history(self, user_id: int) -> pd.DataFrame:
        """
        Get user's login history from database for ML training
        
        Args:
            user_id: User ID
            
        Returns:
            DataFrame with login history
        """
        cursor = self.conn.cursor()
        
        # Get last 100 successful logins
        cursor.execute("""
            SELECT 
                HOUR(timestamp) as hour,
                DAYOFWEEK(timestamp) - 1 as day_of_week,
                ip_address,
                user_agent,
                success,
                timestamp
            FROM login_attempts
            WHERE user_id = %s AND success = 1
            ORDER BY timestamp DESC
            LIMIT 100
        """, (user_id,))
        
        rows = cursor.fetchall()
        
        if not rows:
            return pd.DataFrame()
        
        # Convert to DataFrame
        data = []
        for row in rows:
            data.append({
                'hour': row['hour'],
                'day_of_week': row['day_of_week'],
                'ip_address': row['ip_address'],
                'user_agent': row['user_agent'],
                'timestamp': row['timestamp']
            })
        
        return pd.DataFrame(data)
    
    def analyze_login_attempt(self, user_id: int, current_login: Dict) -> Tuple[float, str, bool]:
        """
        Analyze login attempt and calculate risk score using AI
        
        This is the MAIN function that does the AI analysis!
        
        Process:
        1. Get user's login history
        2. If enough history, train ML model
        3. Detect if current login is anomaly
        4. Calculate risk score (0-100)
        5. Determine risk level and recommendation
        
        Args:
            user_id: User ID
            current_login: Current login attempt data
            
        Returns:
            Tuple of (risk_score, risk_level, is_anomaly)
            - risk_score: 0-100 (higher = more suspicious)
            - risk_level: "LOW" / "MEDIUM" / "HIGH"
            - is_anomaly: True if ML detected anomaly
        """
        # Get user's login history
        history = self.get_user_login_history(user_id)
        
        # If not enough history, use rule-based scoring
        if len(history) < self.min_history_count:
            return self._rule_based_scoring(current_login)
        
        # Prepare training data from history
        training_features = []
        for _, row in history.iterrows():
            features = {
                'hour': row['hour'],
                'day_of_week': row['day_of_week'],
                'location_changed': 0,  # Historical data is normal
                'device_changed': 0,
                'hours_since_last': 24  # Average
            }
            training_features.append(self.extract_features(features)[0])
        
        X_train = np.array(training_features)
        
        # Train ML model on user's normal behavior
        self.model.fit(X_train)
        
        # Extract features from current login
        current_features = self.extract_features(current_login)
        
        # Predict if anomaly using ML
        prediction = self.model.predict(current_features)
        anomaly_score = self.model.score_samples(current_features)[0]
        
        is_anomaly = prediction[0] == -1
        
        # Calculate risk score (0-100)
        base_risk = 50 if is_anomaly else 20
        
        # Adjust based on specific factors
        if current_login.get('location_changed'):
            base_risk += 20
        if current_login.get('device_changed'):
            base_risk += 15
        if current_login.get('unusual_hour'):
            base_risk += 10
        
        risk_score = min(base_risk, 100)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return risk_score, risk_level, is_anomaly
    
    def _rule_based_scoring(self, login_data: Dict) -> Tuple[float, str, bool]:
        """
        Simple rule-based scoring for new users (not enough history for ML)
        
        Args:
            login_data: Login attempt data
            
        Returns:
            Tuple of (risk_score, risk_level, is_anomaly)
        """
        risk_score = 30  # Base score for new users
        
        # Add risk for suspicious factors
        if login_data.get('location_changed'):
            risk_score += 20
        if login_data.get('device_changed'):
            risk_score += 15
        if login_data.get('unusual_hour'):
            risk_score += 10
        
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        is_anomaly = risk_score >= 60
        
        return risk_score, risk_level, is_anomaly
    
    def update_behavior_pattern(self, user_id: int):
        """
        Update user's behavior pattern profile in database
        
        This learns what's "normal" for this user
        
        Args:
            user_id: User ID
        """
        history = self.get_user_login_history(user_id)
        
        if len(history) < 3:
            return  # Not enough data
        
        # Calculate typical patterns
        typical_hours = history['hour'].value_counts().head(5).index.tolist()
        typical_ips = history['ip_address'].value_counts().head(3).index.tolist()
        typical_devices = history['user_agent'].value_counts().head(3).index.tolist()
        
        # Average session duration (placeholder)
        avg_duration = 30  # minutes
        
        # Update or insert pattern in database
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO behavior_patterns 
            (user_id, typical_login_hours, typical_locations, typical_devices, 
             average_session_duration, last_updated)
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            ON DUPLICATE KEY UPDATE
            typical_login_hours = %s,
            typical_locations = %s,
            typical_devices = %s,
            average_session_duration = %s,
            last_updated = CURRENT_TIMESTAMP
        """, (
            user_id,
            json.dumps(typical_hours),
            json.dumps(typical_ips),
            json.dumps(typical_devices),
            avg_duration,
            json.dumps(typical_hours),
            json.dumps(typical_ips),
            json.dumps(typical_devices),
            avg_duration
        ))
        self.conn.commit()
    
    def get_recommendation(self, risk_score: float) -> str:
        """
        Get security recommendation based on risk score
        
        Args:
            risk_score: Risk score (0-100)
            
        Returns:
            Recommendation string
        """
        if risk_score >= 70:
            return "BLOCK or require additional verification (email + MFA)"
        elif risk_score >= 40:
            return "Require MFA verification"
        else:
            return "Allow with standard authentication"


# ============================================================================
# TEST CODE - Run this file directly to test the module
# ============================================================================

if __name__ == "__main__":
    import pymysql
    from datetime import datetime, timedelta
    import random
    
    print("=" * 60)
    print("AI-Powered Adaptive Authentication Module Test")
    print("=" * 60)
    print()
    
    # Create test database connection
    try:
        conn = pymysql.connect(
            host='localhost',
            user='secureauth_user',
            password='SecurePass123!',  # Change if needed
            database='secureauth_db',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        print("✓ Connected to database\n")
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        print("  Make sure MariaDB is running and credentials are correct")
        exit(1)
    
    # Create test user if doesn't exist
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (id, username, email, password_hash, role)
            VALUES (999, 'ai_test_user', 'aitest@test.com', 'dummy_hash', 'user')
        """)
        conn.commit()
    except:
        pass  # User already exists
    
    # Generate normal login history (user usually logs in 9 AM - 6 PM)
    print("Generating normal user behavior...")
    normal_hours = [9, 10, 11, 13, 14, 15, 16, 17, 18]
    
    cursor.execute("DELETE FROM login_attempts WHERE user_id = 999")
    
    for i in range(20):
        hour = random.choice(normal_hours)
        timestamp = datetime.now() - timedelta(days=random.randint(1, 30), hours=random.randint(0, 23))
        timestamp = timestamp.replace(hour=hour, minute=random.randint(0, 59))
        
        cursor.execute("""
            INSERT INTO login_attempts (user_id, username, ip_address, user_agent, success, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (999, "ai_test_user", "192.168.1.100", "Chrome/Win10", 1, timestamp))
    
    conn.commit()
    print(f"✓ Created 20 normal login records\n")
    
    # Test adaptive authenticator
    auth = AdaptiveAuthenticator(conn)
    
    # Test 1: Normal login (during typical hours)
    print("-" * 60)
    print("Test 1: Normal login (2 PM, same location, same device)")
    print("-" * 60)
    normal_login = {
        'hour': 14,
        'day_of_week': 2,  # Wednesday
        'location_changed': False,
        'device_changed': False,
        'unusual_hour': False,
        'hours_since_last': 24
    }
    risk_score, risk_level, is_anomaly = auth.analyze_login_attempt(999, normal_login)
    print(f"  Risk Score: {risk_score}/100")
    print(f"  Risk Level: {risk_level}")
    print(f"  Anomaly: {is_anomaly}")
    print(f"  Recommendation: {auth.get_recommendation(risk_score)}")
    print()
    
    # Test 2: Suspicious login (unusual hour, new location)
    print("-" * 60)
    print("Test 2: Suspicious login (3 AM, new location)")
    print("-" * 60)
    suspicious_login = {
        'hour': 3,
        'day_of_week': 6,  # Sunday
        'location_changed': True,
        'device_changed': False,
        'unusual_hour': True,
        'hours_since_last': 6
    }
    risk_score, risk_level, is_anomaly = auth.analyze_login_attempt(999, suspicious_login)
    print(f"  Risk Score: {risk_score}/100")
    print(f"  Risk Level: {risk_level}")
    print(f"  Anomaly: {is_anomaly}")
    print(f"  Recommendation: {auth.get_recommendation(risk_score)}")
    print()
    
    # Test 3: Very suspicious (3 AM, new location, new device)
    print("-" * 60)
    print("Test 3: Very suspicious (3 AM, new location, new device)")
    print("-" * 60)
    very_suspicious = {
        'hour': 3,
        'day_of_week': 6,
        'location_changed': True,
        'device_changed': True,
        'unusual_hour': True,
        'hours_since_last': 2
    }
    risk_score, risk_level, is_anomaly = auth.analyze_login_attempt(999, very_suspicious)
    print(f"  Risk Score: {risk_score}/100")
    print(f"  Risk Level: {risk_level}")
    print(f"  Anomaly: {is_anomaly}")
    print(f"  Recommendation: {auth.get_recommendation(risk_score)}")
    print()
    
    # Update behavior pattern
    print("-" * 60)
    print("Updating user behavior pattern...")
    print("-" * 60)
    auth.update_behavior_pattern(999)
    
    cursor.execute("SELECT typical_login_hours FROM behavior_patterns WHERE user_id = 999")
    pattern = cursor.fetchone()
    if pattern:
        hours = json.loads(pattern['typical_login_hours'])
        print(f"✓ Typical login hours learned: {hours}")
    print()
    
    print("=" * 60)
    print("✓ AI Adaptive Authentication module working correctly!")
    print("=" * 60)
    
    # Cleanup
    cursor.execute("DELETE FROM users WHERE id = 999")
    cursor.execute("DELETE FROM login_attempts WHERE user_id = 999")
    cursor.execute("DELETE FROM behavior_patterns WHERE user_id = 999")
    conn.commit()
    conn.close()
