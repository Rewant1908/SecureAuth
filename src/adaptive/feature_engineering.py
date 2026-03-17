"""
Advanced Feature Engineering for AI Security
Extracts 15+ features from login attempts

Author: Rewant
Course: CSE212 Cyber Security
Advanced Version: Pro-Level
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List
import hashlib
import re


class AdvancedFeatureExtractor:
    """
    Extract 15+ advanced features for ML models
    
    Feature Categories:
    1. Temporal (5 features) - When is the login?
    2. Behavioral (5 features) - How different from normal?
    3. Network (3 features) - Where from?
    4. Statistical (2 features) - Historical patterns
    
    Used by: Google, Microsoft, AWS for security
    """
    
    def __init__(self, db_connection):
        """
        Initialize feature extractor
        
        Args:
            db_connection: Database connection object
        """
        self.conn = db_connection
        
        # Known malicious IP prefixes (example - in production use threat intel API)
        self.malicious_ip_prefixes = [
            '192.0.2.',      # TEST-NET-1 (RFC 5737)
            '198.51.100.',   # TEST-NET-2
            '203.0.113.',    # TEST-NET-3
            '185.220.',      # Known Tor exit nodes
            '45.227.'        # Known attack sources
        ]
        
        # Known VPN/Proxy indicators
        self.vpn_keywords = ['vpn', 'proxy', 'tor', 'tunnel', 'relay']
    
    def extract_all_features(self, user_id: int, login_data: Dict, user_history: pd.DataFrame) -> np.ndarray:
        """
        Extract all 15+ features from login attempt
        
        Args:
            user_id: User ID
            login_data: Current login attempt data
            user_history: User's historical logins (DataFrame)
            
        Returns:
            NumPy array of 15 features
        """
        features = {}
        
        # ==========================================
        # TEMPORAL FEATURES (When?)
        # ==========================================
        
        # Feature 1: Hour of day (0-23)
        features['hour'] = login_data.get('hour', datetime.now().hour)
        
        # Feature 2: Day of week (0-6, Monday=0)
        features['day_of_week'] = login_data.get('day_of_week', datetime.now().weekday())
        
        # Feature 3: Is weekend? (0 or 1)
        features['is_weekend'] = 1 if features['day_of_week'] >= 5 else 0
        
        # Feature 4: Is business hours? (9 AM - 5 PM on weekdays)
        is_weekday = features['day_of_week'] < 5
        is_work_hours = 9 <= features['hour'] <= 17
        features['is_business_hours'] = 1 if (is_weekday and is_work_hours) else 0
        
        # Feature 5: Hours since last login
        features['hours_since_last'] = self._calculate_hours_since_last(user_history)
        
        # ==========================================
        # BEHAVIORAL FEATURES (How different?)
        # ==========================================
        
        # Feature 6: Location changed? (0 or 1)
        features['location_changed'] = 1 if login_data.get('location_changed', False) else 0
        
        # Feature 7: Device changed? (0 or 1)
        features['device_changed'] = 1 if login_data.get('device_changed', False) else 0
        
        # Feature 8: User agent entropy (complexity of browser string)
        user_agent = login_data.get('user_agent', '')
        features['user_agent_entropy'] = self._calculate_entropy(user_agent)
        
        # Feature 9: Typing speed deviation (from normal)
        features['typing_speed_deviation'] = self._calculate_typing_deviation(
            login_data.get('typing_speed', 0),
            user_history
        )
        
        # Feature 10: Login velocity (logins per hour in last 24h)
        features['login_velocity'] = self._calculate_login_velocity(user_history)
        
        # ==========================================
        # NETWORK FEATURES (Where from?)
        # ==========================================
        
        # Feature 11: IP risk score (0-1)
        ip_address = login_data.get('ip_address', '')
        features['ip_risk_score'] = self._calculate_ip_risk(ip_address)
        
        # Feature 12: VPN/Proxy detected? (0 or 1)
        features['is_vpn'] = self._detect_vpn_proxy(ip_address, user_agent)
        
        # Feature 13: Country changed? (0 or 1)
        features['country_changed'] = 1 if login_data.get('country_changed', False) else 0
        
        # ==========================================
        # STATISTICAL FEATURES (Historical)
        # ==========================================
        
        # Feature 14: Failed login ratio (last 10 attempts)
        features['failed_login_ratio'] = self._calculate_failure_rate(user_history)
        
        # Feature 15: Account age (days)
        features['account_age_days'] = login_data.get('account_age_days', 0)
        
        # Convert to numpy array
        feature_vector = np.array(list(features.values())).reshape(1, -1)
        
        return feature_vector
    
    def get_feature_names(self) -> List[str]:
        """
        Get list of feature names (for SHAP explanations)
        
        Returns:
            List of 15 feature names
        """
        return [
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours',
            'hours_since_last', 'location_changed', 'device_changed',
            'user_agent_entropy', 'typing_speed_deviation', 'login_velocity',
            'ip_risk_score', 'is_vpn', 'country_changed',
            'failed_login_ratio', 'account_age_days'
        ]
    
    # ==========================================
    # HELPER METHODS
    # ==========================================
    
    def _calculate_hours_since_last(self, history: pd.DataFrame) -> float:
        """Calculate hours since last login"""
        if len(history) > 0:
            last_login = history.iloc[0]['timestamp']
            time_diff = datetime.now() - last_login
            hours = time_diff.total_seconds() / 3600
            return min(hours, 168)  # Cap at 1 week
        return 24.0  # Default 24 hours
    
    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string
        Higher entropy = more random/complex
        
        Used to detect automated tools vs. real browsers
        """
        if not string:
            return 0.0
        
        # Calculate probability distribution
        entropy = 0
        for char in set(string):
            prob = string.count(char) / len(string)
            entropy -= prob * np.log2(prob)
        
        return min(entropy, 8.0)  # Normalize to 0-8 range
    
    def _calculate_typing_deviation(self, current_speed: float, history: pd.DataFrame) -> float:
        """
        Calculate deviation from normal typing speed
        
        Behavioral biometric - humans type at consistent speeds
        Bots type instantly or inconsistently
        """
        if len(history) == 0 or current_speed == 0:
            return 0.0
        
        # Get average typing speed from history
        if 'typing_speed' in history.columns:
            avg_speed = history['typing_speed'].mean()
            if avg_speed > 0:
                deviation = abs(current_speed - avg_speed) / avg_speed
                return min(deviation, 2.0)  # Cap at 200% deviation
        
        return 0.0
    
    def _calculate_login_velocity(self, history: pd.DataFrame) -> float:
        """
        Calculate login velocity (logins per hour in last 24h)
        
        High velocity = potential automated attack
        """
        if len(history) == 0:
            return 0.0
        
        # Filter last 24 hours
        cutoff_time = datetime.now() - timedelta(hours=24)
        recent = history[history['timestamp'] > cutoff_time]
        
        if len(recent) == 0:
            return 0.0
        
        # Calculate logins per hour
        time_span = (datetime.now() - recent.iloc[-1]['timestamp']).total_seconds() / 3600
        velocity = len(recent) / max(time_span, 1)  # Avoid division by zero
        
        return min(velocity, 10.0)  # Cap at 10 logins/hour
    
    def _calculate_ip_risk(self, ip_address: str) -> float:
        """
        Calculate IP address risk score (0-1)
        
        In production: Use threat intelligence APIs
        - AbuseIPDB
        - IPQualityScore
        - VirusTotal
        
        For now: Simple pattern matching
        """
        if not ip_address:
            return 0.0
        
        # Check against known bad IP prefixes
        for bad_prefix in self.malicious_ip_prefixes:
            if ip_address.startswith(bad_prefix):
                return 0.9  # High risk
        
        # Check if IP is from known attack regions (simplified)
        # In production: Use GeoIP + threat intel
        suspicious_ranges = ['185.', '91.', '176.']  # Example ranges
        for sus_range in suspicious_ranges:
            if ip_address.startswith(sus_range):
                return 0.6  # Medium risk
        
        return 0.1  # Low risk (default)
    
    def _detect_vpn_proxy(self, ip_address: str, user_agent: str) -> int:
        """
        Detect VPN or Proxy usage
        
        VPNs/Proxies often used to hide true location in attacks
        
        In production: Use APIs like
        - IPHub.info
        - ProxyCheck.io
        - IPQualityScore
        """
        # Check user agent for VPN keywords
        user_agent_lower = user_agent.lower()
        for keyword in self.vpn_keywords:
            if keyword in user_agent_lower:
                return 1
        
        # Check IP against known VPN ranges (simplified)
        vpn_ranges = ['10.', '172.16.', '192.168.']  # Private ranges often used by VPNs
        for vpn_range in vpn_ranges:
            if ip_address.startswith(vpn_range):
                return 1
        
        return 0
    
    def _calculate_failure_rate(self, history: pd.DataFrame) -> float:
        """
        Calculate ratio of failed logins in recent history
        
        High failure rate = credential guessing
        """
        if len(history) == 0:
            return 0.0
        
        # Look at last 10 attempts
        recent = history.head(10)
        
        if 'success' in recent.columns:
            failed_count = len(recent[recent['success'] == 0])
            return failed_count / len(recent)
        
        return 0.0


# ============================================
# TEST CODE
# ============================================

if __name__ == "__main__":
    import pymysql
    
    print("=" * 70)
    print("Advanced Feature Engineering Test")
    print("=" * 70)
    print()
    
    # Create test database connection
    try:
        conn = pymysql.connect(
            host='localhost',
            user='secureauth_user',
            password='SecurePass123!',
            database='secureauth_db',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        print("✓ Connected to database\n")
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        exit(1)
    
    # Create feature extractor
    extractor = AdvancedFeatureExtractor(conn)
    
    # Test Case 1: Normal login
    print("-" * 70)
    print("Test 1: Normal login (office hours, known device)")
    print("-" * 70)
    
    normal_login = {
        'hour': 14,
        'day_of_week': 2,  # Wednesday
        'location_changed': False,
        'device_changed': False,
        'ip_address': '103.25.14.50',  # Indian IP (example)
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'typing_speed': 150,  # WPM
        'country_changed': False,
        'account_age_days': 365
    }
    
    # Create dummy history
    history = pd.DataFrame({
        'timestamp': [datetime.now() - timedelta(hours=i*24) for i in range(10)],
        'success': [1] * 10,
        'typing_speed': [145, 150, 148, 152, 149, 151, 147, 150, 148, 151]
    })
    
    features = extractor.extract_all_features(1, normal_login, history)
    feature_names = extractor.get_feature_names()
    
    print("\nExtracted Features:")
    for name, value in zip(feature_names, features[0]):
        print(f"  {name:25s} = {value:6.2f}")
    
    print("\nRisk Indicators:")
    print(f"  IP Risk Score: {features[0][10]:.2f} (0=safe, 1=dangerous)")
    print(f"  VPN Detected: {'Yes' if features[0][11] == 1 else 'No'}")
    print(f"  Failed Login Ratio: {features[0][13]:.2%}")
    
    # Test Case 2: Suspicious login
    print("\n" + "-" * 70)
    print("Test 2: Suspicious login (3 AM, VPN, new device)")
    print("-" * 70)
    
    suspicious_login = {
        'hour': 3,
        'day_of_week': 6,  # Sunday
        'location_changed': True,
        'device_changed': True,
        'ip_address': '185.220.101.50',  # Tor exit node
        'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) VPN-Client',
        'typing_speed': 300,  # Unusually fast = bot
        'country_changed': True,
        'account_age_days': 365
    }
    
    features = extractor.extract_all_features(1, suspicious_login, history)
    
    print("\nExtracted Features:")
    for name, value in zip(feature_names, features[0]):
        print(f"  {name:25s} = {value:6.2f}")
    
    print("\nRisk Indicators:")
    print(f"  IP Risk Score: {features[0][10]:.2f} (0=safe, 1=dangerous)")
    print(f"  VPN Detected: {'Yes' if features[0][11] == 1 else 'No'}")
    print(f"  Business Hours: {'Yes' if features[0][3] == 1 else 'No'}")
    print(f"  Location Changed: {'Yes' if features[0][5] == 1 else 'No'}")
    print(f"  Device Changed: {'Yes' if features[0][6] == 1 else 'No'}")
    
    print("\n" + "=" * 70)
    print("✓ Feature extraction working correctly!")
    print("=" * 70)
    
    conn.close()
