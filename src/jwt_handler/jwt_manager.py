import jwt
import datetime

class JWTHandler:
    SECRET_KEY = "supersecretkey"
    ALGORITHM = "HS256"

    @staticmethod
    def generate_access_token(user_id, role):
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }
        return jwt.encode(payload, JWTHandler.SECRET_KEY, algorithm=JWTHandler.ALGORITHM)

    @staticmethod
    def generate_refresh_token(user_id):
        payload = {
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }
        return jwt.encode(payload, JWTHandler.SECRET_KEY, algorithm=JWTHandler.ALGORITHM)

    @staticmethod
    def verify_token(token):
        try:
            payload = jwt.decode(token, JWTHandler.SECRET_KEY, algorithms=[JWTHandler.ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
