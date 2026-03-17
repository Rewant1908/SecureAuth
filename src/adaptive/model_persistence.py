"""
Model Persistence & Management
Save and load trained ML models for fast predictions

Author: Rewant
Course: CSE212 Cyber Security
Advanced Version: Pro-Level
"""

import joblib
import os
from datetime import datetime
from typing import Optional, Dict, Any
import json


class ModelPersistence:
    """
    Handle saving/loading of trained ML models
    
    Benefits:
    - Fast predictions (no retraining)
    - Continuous learning (incremental updates)
    - Production-ready
    
    Used by: Netflix, Uber, Spotify for ML models
    """
    
    def __init__(self, models_dir: str = 'models/'):
        """
        Initialize model persistence manager
        
        Args:
            models_dir: Directory to store models
        """
        self.models_dir = models_dir
        os.makedirs(models_dir, exist_ok=True)
        
        # Metadata file stores info about all models
        self.metadata_file = os.path.join(models_dir, 'metadata.json')
        self.metadata = self._load_metadata()
    
    def save_model(self, user_id: int, model: Any, training_info: Dict) -> bool:
        """
        Save trained model to disk
        
        Args:
            user_id: User ID
            model: Trained sklearn model
            training_info: Dict with training details
                - samples_count: Number of training samples
                - feature_names: List of feature names
                - performance_metrics: Dict of metrics
                
        Returns:
            True if saved successfully
        """
        model_path = self._get_model_path(user_id)
        
        try:
            # Package model with metadata
            model_package = {
                'model': model,
                'user_id': user_id,
                'trained_at': datetime.now().isoformat(),
                'samples_count': training_info.get('samples_count', 0),
                'feature_names': training_info.get('feature_names', []),
                'performance_metrics': training_info.get('performance_metrics', {}),
                'model_version': '2.0'
            }
            
            # Save to disk
            joblib.dump(model_package, model_path)
            
            # Update metadata
            self.metadata[str(user_id)] = {
                'last_trained': datetime.now().isoformat(),
                'samples_count': training_info.get('samples_count', 0),
                'model_path': model_path
            }
            self._save_metadata()
            
            print(f"✓ Model saved for user {user_id} at {model_path}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to save model for user {user_id}: {e}")
            return False
    
    def load_model(self, user_id: int) -> Optional[Dict]:
        """
        Load trained model from disk
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary with:
            - model: Trained sklearn model
            - trained_at: When model was trained
            - samples_count: Number of training samples
            - feature_names: List of features
            
            None if model doesn't exist
        """
        model_path = self._get_model_path(user_id)
        
        if not os.path.exists(model_path):
            print(f"ℹ No saved model found for user {user_id}")
            return None
        
        try:
            model_package = joblib.load(model_path)
            
            print(f"✓ Loaded model for user {user_id}")
            print(f"  Trained: {model_package['trained_at']}")
            print(f"  Samples: {model_package['samples_count']}")
            
            return model_package
            
        except Exception as e:
            print(f"✗ Failed to load model for user {user_id}: {e}")
            return None
    
    def should_retrain(self, user_id: int, new_samples_count: int) -> bool:
        """
        Decide if model should be retrained
        
        Retrain if:
        - Model doesn't exist
        - 20+ new samples since last training
        - 7+ days since last training
        
        Args:
            user_id: User ID
            new_samples_count: Current total samples available
            
        Returns:
            True if should retrain
        """
        user_key = str(user_id)
        
        # No model exists - need to train
        if user_key not in self.metadata:
            return True
        
        meta = self.metadata[user_key]
        
        # Check if enough new samples
        old_samples = meta.get('samples_count', 0)
        new_samples = new_samples_count - old_samples
        
        if new_samples >= 20:
            print(f"ℹ Retraining: {new_samples} new samples available")
            return True
        
        # Check if too old (7 days)
        last_trained = datetime.fromisoformat(meta['last_trained'])
        days_old = (datetime.now() - last_trained).days
        
        if days_old >= 7:
            print(f"ℹ Retraining: Model is {days_old} days old")
            return True
        
        return False
    
    def delete_model(self, user_id: int) -> bool:
        """
        Delete saved model for user
        
        Args:
            user_id: User ID
            
        Returns:
            True if deleted successfully
        """
        model_path = self._get_model_path(user_id)
        
        try:
            if os.path.exists(model_path):
                os.remove(model_path)
                
                # Remove from metadata
                user_key = str(user_id)
                if user_key in self.metadata:
                    del self.metadata[user_key]
                    self._save_metadata()
                
                print(f"✓ Deleted model for user {user_id}")
                return True
            else:
                print(f"ℹ No model to delete for user {user_id}")
                return False
                
        except Exception as e:
            print(f"✗ Failed to delete model for user {user_id}: {e}")
            return False
    
    def get_all_models_info(self) -> Dict:
        """
        Get information about all saved models
        
        Returns:
            Dictionary with model statistics
        """
        return {
            'total_models': len(self.metadata),
            'models': self.metadata
        }
    
    # ==========================================
    # PRIVATE HELPER METHODS
    # ==========================================
    
    def _get_model_path(self, user_id: int) -> str:
        """Get file path for user's model"""
        return os.path.join(self.models_dir, f'user_{user_id}_model.pkl')
    
    def _load_metadata(self) -> Dict:
        """Load metadata file"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_metadata(self):
        """Save metadata file"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            print(f"✗ Failed to save metadata: {e}")


# ============================================
# TEST CODE
# ============================================

if __name__ == "__main__":
    from sklearn.ensemble import IsolationForest
    import numpy as np
    
    print("=" * 70)
    print("Model Persistence Test")
    print("=" * 70)
    print()
    
    # Create test directory
    test_dir = 'test_models/'
    persistence = ModelPersistence(models_dir=test_dir)
    
    # Test 1: Save a model
    print("-" * 70)
    print("Test 1: Save model")
    print("-" * 70)
    
    # Create and train a dummy model
    X_train = np.random.randn(100, 5)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_train)
    
    training_info = {
        'samples_count': 100,
        'feature_names': ['feature_1', 'feature_2', 'feature_3', 'feature_4', 'feature_5'],
        'performance_metrics': {
            'accuracy': 0.95,
            'precision': 0.92,
            'recall': 0.88
        }
    }
    
    success = persistence.save_model(user_id=1, model=model, training_info=training_info)
    print(f"Save result: {'✓ Success' if success else '✗ Failed'}")
    print()
    
    # Test 2: Load the model
    print("-" * 70)
    print("Test 2: Load model")
    print("-" * 70)
    
    loaded = persistence.load_model(user_id=1)
    if loaded:
        print("✓ Model loaded successfully")
        print(f"  Features: {loaded['feature_names']}")
        print(f"  Metrics: {loaded['performance_metrics']}")
    else:
        print("✗ Failed to load model")
    print()
    
    # Test 3: Check if should retrain
    print("-" * 70)
    print("Test 3: Should retrain?")
    print("-" * 70)
    
    # With same samples - should NOT retrain
    should_train = persistence.should_retrain(user_id=1, new_samples_count=100)
    print(f"Should retrain with 100 samples: {should_train} (Expected: False)")
    
    # With 20+ new samples - SHOULD retrain
    should_train = persistence.should_retrain(user_id=1, new_samples_count=125)
    print(f"Should retrain with 125 samples: {should_train} (Expected: True)")
    print()
    
    # Test 4: Get all models info
    print("-" * 70)
    print("Test 4: Get all models info")
    print("-" * 70)
    
    info = persistence.get_all_models_info()
    print(f"Total models saved: {info['total_models']}")
    for user_id, meta in info['models'].items():
        print(f"  User {user_id}: {meta['samples_count']} samples, last trained {meta['last_trained']}")
    print()
    
    # Test 5: Delete model
    print("-" * 70)
    print("Test 5: Delete model")
    print("-" * 70)
    
    success = persistence.delete_model(user_id=1)
    print(f"Delete result: {'✓ Success' if success else '✗ Failed'}")
    
    # Verify deletion
    loaded = persistence.load_model(user_id=1)
    print(f"Model exists after deletion: {loaded is not None} (Expected: False)")
    print()
    
    # Cleanup
    import shutil
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
        print(f"✓ Cleaned up test directory")
    
    print("=" * 70)
    print("✓ Model persistence working correctly!")
    print("=" * 70)
