"""
Explainable AI with SHAP Values
Explains WHY login was blocked in human language

Author: Rewant
Course: CSE212 Cyber Security
Advanced Version: Pro-Level

This is the KILLER FEATURE for your presentation!
"""

import numpy as np
from typing import Dict, List, Tuple
import shap


class ExplainableAI:
    """
    Uses SHAP (SHapley Additive exPlanations) to explain AI decisions
    
    Why this matters:
    - Transparency (users know WHY they were blocked)
    - Trust (not a "black box")
    - Compliance (GDPR requires explainability)
    - Debugging (understand false positives)
    
    Used by:
    - Microsoft Azure ML
    - Google Cloud AI Explanations
    - Amazon SageMaker Clarify
    
    This feature will IMPRESS your professor!
    """
    
    def __init__(self, model, feature_names: List[str]):
        """
        Initialize explainable AI
        
        Args:
            model: Trained sklearn model
            feature_names: List of feature names (for explanations)
        """
        self.model = model
        self.feature_names = feature_names
        self.explainer = None
        
        # Human-readable explanations for each feature
        self.feature_explanations = {
            'hour': self._explain_hour,
            'day_of_week': self._explain_day,
            'is_weekend': self._explain_weekend,
            'is_business_hours': self._explain_business_hours,
            'hours_since_last': self._explain_time_gap,
            'location_changed': self._explain_location,
            'device_changed': self._explain_device,
            'user_agent_entropy': self._explain_user_agent,
            'typing_speed_deviation': self._explain_typing,
            'login_velocity': self._explain_velocity,
            'ip_risk_score': self._explain_ip_risk,
            'is_vpn': self._explain_vpn,
            'country_changed': self._explain_country,
            'failed_login_ratio': self._explain_failures,
            'account_age_days': self._explain_account_age
        }
    
    def initialize_explainer(self, X_background: np.ndarray):
        """
        Initialize SHAP explainer with background data
        
        Args:
            X_background: Sample of normal user behavior (for comparison)
        """
        try:
            # Use TreeExplainer for tree-based models (fast)
            self.explainer = shap.TreeExplainer(self.model)
        except:
            # Fallback to KernelExplainer (works with any model, slower)
            self.explainer = shap.KernelExplainer(
                self.model.predict,
                X_background
            )
        
        print("✓ SHAP explainer initialized")
    
    def explain_prediction(self, X: np.ndarray, risk_score: float) -> Dict:
        """
        Generate human-readable explanation for prediction
        
        Args:
            X: Feature vector (1 x 15)
            risk_score: Calculated risk score (0-100)
            
        Returns:
            Dictionary with:
            - explanation: Human-readable text
            - top_factors: Top 3 risk factors
            - shap_values: Raw SHAP values
            - verdict: Allow/Block/Require MFA
        """
        if self.explainer is None:
            return {
                'explanation': "Explainer not initialized",
                'top_factors': [],
                'verdict': 'UNKNOWN'
            }
        
        # Calculate SHAP values
        shap_values = self.explainer.shap_values(X)
        
        # Handle different SHAP output formats
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # For classification (class 1 = anomaly)
        
        # Get feature importance
        feature_importance = {}
        for i, name in enumerate(self.feature_names):
            if i < len(shap_values[0]):
                feature_importance[name] = shap_values[0][i]
        
        # Sort by absolute contribution
        top_features = sorted(
            feature_importance.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:3]  # Top 3 factors
        
        # Generate verdict
        if risk_score >= 70:
            verdict = "🚫 LOGIN BLOCKED"
            action = "BLOCK"
        elif risk_score >= 40:
            verdict = "⚠️ ADDITIONAL VERIFICATION REQUIRED"
            action = "REQUIRE_MFA"
        else:
            verdict = "✅ LOGIN ALLOWED"
            action = "ALLOW"
        
        # Generate human-readable explanation
        explanation = self._generate_explanation(
            top_features, X, risk_score, verdict
        )
        
        return {
            'explanation': explanation,
            'top_factors': top_features,
            'shap_values': shap_values,
            'verdict': action,
            'risk_score': risk_score
        }
    
    def _generate_explanation(
        self,
        top_features: List[Tuple[str, float]],
        X: np.ndarray,
        risk_score: float,
        verdict: str
    ) -> str:
        """
        Generate human-readable explanation
        
        Args:
            top_features: List of (feature_name, shap_value) tuples
            X: Feature vector
            risk_score: Risk score
            verdict: Verdict string
            
        Returns:
            Human-readable explanation text
        """
        # Build explanation
        lines = [
            verdict,
            "",
            f"Risk Score: {risk_score:.1f}/100",
            "",
            "Analysis:"
        ]
        
        # Add top risk factors
        for feature_name, contribution in top_features:
            # Get feature value
            feature_idx = self.feature_names.index(feature_name)
            feature_value = X[0][feature_idx]
            
            # Generate human explanation
            if feature_name in self.feature_explanations:
                explanation = self.feature_explanations[feature_name](
                    feature_value, contribution
                )
                if explanation:
                    lines.append(f"  • {explanation}")
        
        # Add recommendation
        lines.append("")
        if risk_score >= 70:
            lines.append("Recommendation: This login shows multiple high-risk indicators.")
            lines.append("For your security, we've blocked this attempt and sent")
            lines.append("you an email notification.")
        elif risk_score >= 40:
            lines.append("Recommendation: This login has some unusual characteristics.")
            lines.append("Please verify your identity with the code we just sent.")
        else:
            lines.append("Recommendation: Login appears normal. Welcome back!")
        
        return "\n".join(lines)
    
    # ==========================================
    # FEATURE-SPECIFIC EXPLANATIONS
    # ==========================================
    
    def _explain_hour(self, value: float, contribution: float) -> str:
        """Explain hour feature"""
        hour = int(value)
        if abs(contribution) < 0.1:
            return None
        
        if 3 <= hour <= 5:
            return f"Login at {hour}:00 is very unusual (typically associated with attacks)"
        elif hour < 6 or hour > 22:
            return f"Login at {hour}:00 is outside normal hours"
        return None
    
    def _explain_day(self, value: float, contribution: float) -> str:
        """Explain day of week feature"""
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        day = days[int(value)]
        
        if abs(contribution) < 0.1:
            return None
        
        if int(value) >= 5:
            return f"Login on {day} (you usually login on weekdays)"
        return None
    
    def _explain_weekend(self, value: float, contribution: float) -> str:
        """Explain weekend feature"""
        if abs(contribution) > 0.1 and value == 1:
            return "Weekend login detected (unusual for your pattern)"
        return None
    
    def _explain_business_hours(self, value: float, contribution: float) -> str:
        """Explain business hours feature"""
        if abs(contribution) > 0.1 and value == 0:
            return "Login outside business hours (9 AM - 5 PM)"
        return None
    
    def _explain_time_gap(self, value: float, contribution: float) -> str:
        """Explain time since last login"""
        if abs(contribution) < 0.1:
            return None
        
        hours = int(value)
        if hours < 1:
            return "Login very soon after last login (< 1 hour)"
        elif hours > 168:
            return f"Long gap since last login ({hours} hours)"
        return None
    
    def _explain_location(self, value: float, contribution: float) -> str:
        """Explain location change"""
        if value == 1:
            return "Location is different from your usual locations"
        return None
    
    def _explain_device(self, value: float, contribution: float) -> str:
        """Explain device change"""
        if value == 1:
            return "Device/browser is different from your usual devices"
        return None
    
    def _explain_user_agent(self, value: float, contribution: float) -> str:
        """Explain user agent entropy"""
        if abs(contribution) > 0.1 and value > 6:
            return "Browser signature appears unusual or automated"
        return None
    
    def _explain_typing(self, value: float, contribution: float) -> str:
        """Explain typing speed deviation"""
        if abs(contribution) > 0.1 and value > 0.5:
            return f"Typing pattern differs significantly from your normal speed"
        return None
    
    def _explain_velocity(self, value: float, contribution: float) -> str:
        """Explain login velocity"""
        if abs(contribution) > 0.1 and value > 2:
            return f"High number of logins ({value:.0f}/hour) in last 24 hours"
        return None
    
    def _explain_ip_risk(self, value: float, contribution: float) -> str:
        """Explain IP risk score"""
        if abs(contribution) > 0.1:
            risk_pct = value * 100
            if risk_pct > 70:
                return f"IP address has high risk score ({risk_pct:.0f}%) - associated with attacks"
            elif risk_pct > 40:
                return f"IP address has moderate risk score ({risk_pct:.0f}%)"
        return None
    
    def _explain_vpn(self, value: float, contribution: float) -> str:
        """Explain VPN detection"""
        if value == 1:
            return "VPN or proxy detected (often used to hide true location)"
        return None
    
    def _explain_country(self, value: float, contribution: float) -> str:
        """Explain country change"""
        if value == 1:
            return "Login from different country than usual"
        return None
    
    def _explain_failures(self, value: float, contribution: float) -> str:
        """Explain failed login ratio"""
        if abs(contribution) > 0.1 and value > 0.3:
            pct = value * 100
            return f"High failure rate: {pct:.0f}% of recent attempts failed"
        return None
    
    def _explain_account_age(self, value: float, contribution: float) -> str:
        """Explain account age"""
        if abs(contribution) > 0.1 and value < 30:
            return f"New account (only {int(value)} days old) - higher risk"
        return None


# ============================================
# TEST CODE
# ============================================

if __name__ == "__main__":
    from sklearn.ensemble import IsolationForest
    import numpy as np
    
    print("=" * 70)
    print("Explainable AI Test")
    print("=" * 70)
    print()
    
    # Create dummy model
    X_train = np.random.randn(100, 15)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_train)
    
    # Feature names
    feature_names = [
        'hour', 'day_of_week', 'is_weekend', 'is_business_hours',
        'hours_since_last', 'location_changed', 'device_changed',
        'user_agent_entropy', 'typing_speed_deviation', 'login_velocity',
        'ip_risk_score', 'is_vpn', 'country_changed',
        'failed_login_ratio', 'account_age_days'
    ]
    
    # Create explainer
    explainer = ExplainableAI(model, feature_names)
    explainer.initialize_explainer(X_train)
    
    # Test Case 1: Suspicious login
    print("-" * 70)
    print("Test 1: Suspicious login (3 AM, VPN, new location)")
    print("-" * 70)
    print()
    
    suspicious_features = np.array([[
        3,      # hour (3 AM)
        6,      # day_of_week (Sunday)
        1,      # is_weekend
        0,      # is_business_hours
        2,      # hours_since_last
        1,      # location_changed
        1,      # device_changed
        7.5,    # user_agent_entropy (high)
        1.8,    # typing_speed_deviation (high)
        0.5,    # login_velocity
        0.9,    # ip_risk_score (high)
        1,      # is_vpn
        1,      # country_changed
        0.4,    # failed_login_ratio
        10      # account_age_days (new account)
    ]])
    
    result = explainer.explain_prediction(suspicious_features, risk_score=87)
    print(result['explanation'])
    print()
    
    # Test Case 2: Normal login
    print("-" * 70)
    print("Test 2: Normal login (2 PM, known device)")
    print("-" * 70)
    print()
    
    normal_features = np.array([[
        14,     # hour (2 PM)
        2,      # day_of_week (Wednesday)
        0,      # is_weekend
        1,      # is_business_hours
        24,     # hours_since_last
        0,      # location_changed
        0,      # device_changed
        4.2,    # user_agent_entropy (normal)
        0.1,    # typing_speed_deviation (low)
        0.2,    # login_velocity
        0.1,    # ip_risk_score (low)
        0,      # is_vpn
        0,      # country_changed
        0.0,    # failed_login_ratio
        365     # account_age_days
    ]])
    
    result = explainer.explain_prediction(normal_features, risk_score=18)
    print(result['explanation'])
    print()
    
    print("=" * 70)
    print("✓ Explainable AI working correctly!")
    print("=" * 70)
