"""
Configuration classes for Flask application environments.
"""
import os
import secrets


class Config:
    """Base configuration with secure defaults."""
    # Generate a fallback cryptographic key if not provided via environment
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    
    # Server network settings
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", 5000))
    
    # Input validation constraints (DoS mitigation)
    MAX_PASSWORD_LENGTH = int(os.environ.get("MAX_PASSWORD_LENGTH", 256))
    MAX_CONTENT_LENGTH = 64 * 1024  # 64 KB maximum payload to block memory exhaustion
    
    # Analysis options
    ENABLE_ZXCVBN = os.environ.get("ENABLE_ZXCVBN", "True").lower() in ("true", "1", "yes")
    MAX_HISTORY_ENTRIES = int(os.environ.get("MAX_HISTORY_ENTRIES", 50))
    
    # Session cookie security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Set to True in production HTTPS
    
    # Database for safe metadata logging (non-sensitive metrics only)
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///:memory:")


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing environment configuration."""
    DEBUG = False
    TESTING = True
    SECRET_KEY = "test-secret-key-for-unit-testing-only"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


class ProductionConfig(Config):
    """Production environment configuration with hardened security defaults."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"


def get_config():
    """Retrieve configuration class based on FLASK_ENV or APP_ENV."""
    env = os.environ.get("FLASK_ENV", os.environ.get("APP_ENV", "development")).lower()
    if env == "production":
        return ProductionConfig
    elif env == "testing":
        return TestingConfig
    return DevelopmentConfig
