"""Production configuration for PCS.

This module provides production-ready settings and security enhancements.
"""

import os
import secrets


def get_secret_key() -> str:
    """Get secret key from environment or generate a secure one."""
    secret = os.getenv('PCS_SECRET_KEY')
    if not secret:
        # Generate a random secret key if not provided
        secret = secrets.token_urlsafe(32)
        print("WARNING: Using auto-generated secret key. Set PCS_SECRET_KEY environment variable for production.")
    return secret


def get_admin_password() -> str:
    """Get admin password from environment or use default."""
    password = os.getenv('PCS_ADMIN_PASSWORD', 'admin')
    if password == 'admin':
        print("WARNING: Using default admin password. Set PCS_ADMIN_PASSWORD environment variable for production.")
    return password


# Production settings
SECRET_KEY = get_secret_key()
ADMIN_PASSWORD = get_admin_password()
DEBUG = os.getenv('PCS_DEBUG', 'false').lower() == 'true'
HOST = os.getenv('PCS_HOST', '0.0.0.0')
PORT = int(os.getenv('PCS_PORT', '8000'))
WORKERS = int(os.getenv('PCS_WORKERS', '4'))
