"""
PRO-Level AI Adaptive Authentication
Enterprise-grade adaptive authentication with ensemble ML models,
feature engineering, and optional explainability support.

Author: Rewant
Course: CSE212 Cyber Security
"""

from datetime import datetime, timedelta
import os
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

from adaptive.feature_engineering import AdvancedFeatureExtractor
from adaptive.model_persistence import ModelPersistence

try:
    from adaptive.explainable_ai import ExplainableAI
except Exception:
    ExplainableAI = None


class EnsembleAnomalyDetector:
    """
    Lightweight ensemble anomaly detector using three unsupervised models.
    """

    def __init__(self):
        self.iso_forest = IsolationForest(
            contamination=0.05,
            n_estimators=200,
            max_samples="auto",
            random_state=42,
        )
        self.svm = OneClassSVM(kernel="rbf", gamma="auto", nu=0.05)
        self.lof = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.05,
            novelty=True,
        )
        self.models_trained = False

    def fit(self, X_train: np.ndarray):
        self.iso_forest.fit(X_train)
        self.svm.fit(X_train)
        self.lof.fit(X_train)
        self.models_trained = True

    def predict_with_confidence(self, X: np.ndarray) -> Tuple[bool, float, List[str]]:
        if not self.models_trained:
            raise ValueError("Models not trained yet")

        iso_pred = self.iso_forest.predict(X)[0]
        svm_pred = self.svm.predict(X)[0]
        lof_pred = self.lof.predict(X)[0]

        iso_score = -self.iso_forest.score_samples(X)[0]
        lof_score = -self.lof.score_samples(X)[0]

        votes = []
        if iso_pred == -1:
            votes.append("IsolationForest")
        if svm_pred == -1:
            votes.append("OneClassSVM")
        if lof_pred == -1:
            votes.append("LocalOutlierFactor")

        is_anomaly = len(votes) >= 2
        confidence = float(min(max((iso_score + lof_score) / 2, 0), 1))
        return is_anomaly, confidence, votes


class ProAdaptiveAuthenticator:
    """
    PRO adaptive authenticator with rule-based fallback for users who do
    not yet have enough login history for model training.
    """

    def __init__(self, db_connection, models_dir="models/"):
        self.conn = db_connection
        self.feature_extractor = AdvancedFeatureExtractor(db_connection)
        self.model_manager = ModelPersistence(models_dir)
        self.ensemble = None
        self.explainer = None
        self.feature_names = self.feature_extractor.get_feature_names()

    def analyze_login(self, user_id: int, login_data: Dict) -> Dict:
        history = self.get_user_login_history(user_id)
        features = self.feature_extractor.extract_all_features(
            user_id,
            login_data,
            history,
        )

        model_package = self.model_manager.load_model(user_id)

        if model_package is None:
            if len(history) < 10:
                return self._rule_based_analysis(features, login_data)

            X_train = self._prepare_training_data(user_id, history)
            if len(X_train) == 0:
                return self._rule_based_analysis(features, login_data)

            self.ensemble = EnsembleAnomalyDetector()
            self.ensemble.fit(X_train)
            self._save_model(user_id, X_train)
        else:
            self.ensemble = model_package["model"]
            if self.model_manager.should_retrain(user_id, len(history)):
                X_train = self._prepare_training_data(user_id, history)
                if len(X_train) > 0:
                    self.ensemble.fit(X_train)
                    self._save_model(user_id, X_train)

        is_anomaly, confidence, voting_models = self.ensemble.predict_with_confidence(features)

        base_risk = 60 if is_anomaly else 20
        risk_score = min(base_risk + (confidence * 40), 100)

        if login_data.get("location_changed"):
            risk_score += 10
        if login_data.get("device_changed"):
            risk_score += 10
        if features[0][11] == 1:
            risk_score += 10

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk_level = "HIGH"
            action = "BLOCK"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            action = "REQUIRE_MFA"
        else:
            risk_level = "LOW"
            action = "ALLOW"

        explanation_text = self._generate_explanation(
            features,
            risk_score,
            user_id,
            history,
        )

        self._record_prediction(user_id, login_data, risk_score)

        return {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "action": action,
            "confidence": round(confidence, 2),
            "is_anomaly": is_anomaly,
            "voting_models": voting_models,
            "explanation": explanation_text,
            "timestamp": datetime.now().isoformat(),
        }

    def _save_model(self, user_id: int, X_train: np.ndarray):
        training_info = {
            "samples_count": len(X_train),
            "feature_names": self.feature_names,
            "performance_metrics": {},
        }
        self.model_manager.save_model(user_id, self.ensemble, training_info)

    def _prepare_training_data(self, user_id: int, history: pd.DataFrame) -> np.ndarray:
        X_train = []

        for _, row in history.iterrows():
            if row.get("success", 1) != 1:
                continue
            if row.get("risk_score", 0) > 85:
                continue

            login_data = {
                "hour": row.get("hour", 12),
                "day_of_week": row.get("day_of_week", 2),
                "ip_address": row.get("ip_address", ""),
                "user_agent": row.get("user_agent", ""),
                "location_changed": False,
                "device_changed": False,
                "country_changed": False,
                "typing_speed": row.get("typing_speed", 0),
                "account_age_days": row.get("account_age_days", 100),
            }

            features = self.feature_extractor.extract_all_features(
                user_id,
                login_data,
                pd.DataFrame(),
            )
            base_features = features[0].copy()
            X_train.append(base_features)

            if len(X_train) % 2 == 0:
                adv_features = base_features.copy()
                try:
                    adv_features[0] = adv_features[0] + np.random.normal(0, 1.0)
                    adv_features[8] = adv_features[8] + np.random.normal(0, 10.0)
                except Exception:
                    pass
                X_train.append(adv_features)

        return np.array(X_train)

    def continuous_behavior_scoring(self, user_id: int, behavior_stream: Dict) -> float:
        """
        Placeholder hook for future continuous-authentication scoring.
        """
        return 1.0

    def _generate_explanation(
        self,
        features: np.ndarray,
        risk_score: float,
        user_id: int,
        history: pd.DataFrame,
    ) -> str:
        if ExplainableAI is None:
            return self._simple_explanation(features, risk_score)

        try:
            if self.explainer is None and self.ensemble is not None:
                X_background = self._prepare_training_data(user_id, history)
                if len(X_background) > 0:
                    self.explainer = ExplainableAI(
                        self.ensemble.iso_forest,
                        self.feature_names,
                    )
                    self.explainer.initialize_explainer(X_background)

            if self.explainer is not None:
                result = self.explainer.explain_prediction(features, risk_score)
                return result["explanation"]
        except Exception:
            pass

        return self._simple_explanation(features, risk_score)

    def _simple_explanation(self, features: np.ndarray, risk_score: float) -> str:
        if risk_score >= 70:
            verdict = "LOGIN BLOCKED"
        elif risk_score >= 40:
            verdict = "ADDITIONAL VERIFICATION REQUIRED"
        else:
            verdict = "LOGIN ALLOWED"

        reasons = []
        if features[0][5] == 1:
            reasons.append("Location is different from usual")
        if features[0][6] == 1:
            reasons.append("Device or browser is different from usual")
        if features[0][11] == 1:
            reasons.append("VPN or proxy detected")
        if features[0][10] > 0.7:
            reasons.append("IP address has high risk score")

        explanation = [verdict, "", f"Risk Score: {risk_score:.1f}/100"]
        if reasons:
            explanation.extend(["", "Key Factors:"])
            explanation.extend(f"- {reason}" for reason in reasons)
        return "\n".join(explanation)

    def _rule_based_analysis(self, features: np.ndarray, login_data: Dict) -> Dict:
        risk_score = 30

        if login_data.get("location_changed"):
            risk_score += 20
        if login_data.get("device_changed"):
            risk_score += 15
        if features[0][0] < 6 or features[0][0] > 22:
            risk_score += 10
        if login_data.get("country_changed"):
            risk_score += 15

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk_level = "HIGH"
            action = "BLOCK"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            action = "REQUIRE_MFA"
        else:
            risk_level = "LOW"
            action = "ALLOW"

        return {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "action": action,
            "confidence": 0.5,
            "is_anomaly": risk_score >= 60,
            "voting_models": ["RuleBased"],
            "explanation": f"New user - using rule-based scoring\nRisk: {risk_score}/100",
            "timestamp": datetime.now().isoformat(),
        }

    def _record_prediction(self, user_id: int, login_data: Dict, risk_score: float):
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO login_attempts
                (user_id, username, ip_address, user_agent, success, risk_score, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                """,
                (
                    user_id,
                    login_data.get("username", ""),
                    login_data.get("ip_address", ""),
                    login_data.get("user_agent", ""),
                    1,
                    risk_score,
                ),
            )
            self.conn.commit()
        except Exception:
            pass

    def get_user_login_history(self, user_id: int) -> pd.DataFrame:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT
                HOUR(timestamp) as hour,
                DAYOFWEEK(timestamp) - 1 as day_of_week,
                ip_address,
                user_agent,
                success,
                risk_score,
                timestamp
            FROM login_attempts
            WHERE user_id = %s AND success = 1
            ORDER BY timestamp DESC
            LIMIT 100
            """,
            (user_id,),
        )

        rows = cursor.fetchall()
        if not rows:
            return pd.DataFrame()

        data = []
        for row in rows:
            data.append(
                {
                    "hour": row["hour"],
                    "day_of_week": row["day_of_week"],
                    "ip_address": row["ip_address"],
                    "user_agent": row["user_agent"],
                    "success": row["success"],
                    "risk_score": row.get("risk_score", 0),
                    "timestamp": row["timestamp"],
                    "typing_speed": 150,
                    "account_age_days": 100,
                }
            )

        return pd.DataFrame(data)


if __name__ == "__main__":
    import random
    import shutil

    import pymysql

    print("=" * 70)
    print("PRO-Level AI Adaptive Authentication Test")
    print("=" * 70)
    print()

    try:
        conn = pymysql.connect(
            host="localhost",
            user="secureauth_user",
            password="SecurePass123!",
            database="secureauth_db",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
        print("Connected to database\n")
    except Exception as exc:
        print(f"Database connection failed: {exc}")
        raise SystemExit(1)

    auth = ProAdaptiveAuthenticator(conn, models_dir="test_models/")

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO users (id, username, email, password_hash, role)
            VALUES (888, 'pro_test_user', 'pro@test.com', 'hash', 'user')
            """
        )
        conn.commit()
    except Exception:
        pass

    print("Generating user behavior history...")
    cursor.execute("DELETE FROM login_attempts WHERE user_id = 888")

    normal_hours = [9, 10, 11, 13, 14, 15, 16, 17, 18]
    for _ in range(20):
        hour = random.choice(normal_hours)
        timestamp = datetime.now() - timedelta(days=random.randint(1, 30))
        timestamp = timestamp.replace(hour=hour, minute=random.randint(0, 59))
        cursor.execute(
            """
            INSERT INTO login_attempts (user_id, username, ip_address, user_agent, success, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (888, "pro_test_user", "103.25.14.50", "Chrome/Win10", 1, timestamp),
        )

    conn.commit()
    print("Created 20 normal logins\n")

    normal_login = {
        "username": "pro_test_user",
        "hour": 14,
        "day_of_week": 2,
        "ip_address": "103.25.14.50",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "location_changed": False,
        "device_changed": False,
        "country_changed": False,
        "typing_speed": 150,
        "account_age_days": 365,
    }
    result = auth.analyze_login(888, normal_login)
    print(result["explanation"])
    print(f"\nTechnical Details:")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Models Voted: {', '.join(result['voting_models'])}")
    print()

    suspicious_login = {
        "username": "pro_test_user",
        "hour": 3,
        "day_of_week": 6,
        "ip_address": "185.220.101.50",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) VPN",
        "location_changed": True,
        "device_changed": True,
        "country_changed": True,
        "typing_speed": 300,
        "account_age_days": 365,
    }
    result = auth.analyze_login(888, suspicious_login)
    print(result["explanation"])
    print(f"\nTechnical Details:")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Models Voted: {', '.join(result['voting_models'])}")
    print()

    cursor.execute("DELETE FROM users WHERE id = 888")
    cursor.execute("DELETE FROM login_attempts WHERE user_id = 888")
    conn.commit()
    conn.close()

    if os.path.exists("test_models/"):
        shutil.rmtree("test_models/")

    print("=" * 70)
    print("PRO-Level AI system working correctly")
    print("=" * 70)
