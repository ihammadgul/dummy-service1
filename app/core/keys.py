"""RSA Key Management for Auth Service (Service1)"""
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from app.core.config import settings


class RSAKeyManager:
    """Manages RSA private and public keys for JWT signing"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.kid = None  # Key ID
        self._load_keys()
    
    def _load_keys(self):
        """Load RSA keys from files"""
        try:
            # Load private key
            with open(settings.PRIVATE_KEY_PATH, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # Load public key
            with open(settings.PUBLIC_KEY_PATH, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            # Generate key ID from public key
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.kid = hashlib.sha256(public_pem).hexdigest()[:16]
            
        except FileNotFoundError as e:
            raise Exception(f"RSA key files not found. Please generate keys first: {e}")
    
    def get_private_key_pem(self) -> str:
        """Get private key in PEM format as string"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format as string"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def get_jwks(self) -> dict:
        """Get public key in JWKS format"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        public_numbers = self.public_key.public_numbers()
        
        # Convert to base64url encoding
        import base64
        
        def int_to_base64url(val: int) -> str:
            """Convert integer to base64url encoded string"""
            # Get bytes representation
            byte_length = (val.bit_length() + 7) // 8
            val_bytes = val.to_bytes(byte_length, byteorder='big')
            # Base64url encode
            return base64.urlsafe_b64encode(val_bytes).decode('utf-8').rstrip('=')
        
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": self.kid,
                    "alg": settings.ALGORITHM,
                    "n": int_to_base64url(public_numbers.n),
                    "e": int_to_base64url(public_numbers.e),
                }
            ]
        }


# Global instance
key_manager = RSAKeyManager()
