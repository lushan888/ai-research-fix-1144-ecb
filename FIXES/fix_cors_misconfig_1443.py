"""
Fix for Issue #1443 - CORS Misconfiguration + Origin Reflection → Credential Theft
Agent: lushan888
Bounty: $120 USD

Fix: Restrict CORS to a whitelist of allowed origins.
Never reflect the Origin header in Access-Control-Allow-Origin.
"""

import re
from typing import List, Optional
from urllib.parse import urlparse


class SecureCorsMiddleware:
    """
    Secure CORS middleware that prevents credential theft via origin reflection.
    
    Security measures:
    1. Never reflects the Origin header in Access-Control-Allow-Origin
    2. Uses a strict whitelist of allowed origins
    3. Validates origin format and rejects wildcards
    4. Restricts allowed methods and headers to minimum required
    5. Sets Vary: Origin header for proper cache behavior
    """
    
    # Default whitelist - configure based on your application
    DEFAULT_ALLOWED_ORIGINS = [
        'https://app.example.com',
        'https://admin.example.com',
        'http://localhost:3000',
        'http://localhost:5000',
    ]
    
    def __init__(self, allowed_origins: Optional[List[str]] = None):
        self.allowed_origins = allowed_origins or self.DEFAULT_ALLOWED_ORIGINS.copy()
        
        # Validate that no wildcards are in the whitelist
        for origin in self.allowed_origins:
            if '*' in origin:
                raise ValueError(f"Wildcard origin not allowed in CORS whitelist: {origin}")
    
    def is_origin_allowed(self, origin: str) -> bool:
        """
        Check if an origin is in the whitelist.
        This is a strict comparison - no wildcard matching, no prefix matching.
        """
        if not origin:
            return False
        
        # Normalize by removing trailing slash
        origin = origin.rstrip('/')
        
        # Validate origin format
        try:
            parsed = urlparse(origin)
            if not parsed.scheme or not parsed.netloc:
                return False
            if parsed.scheme not in ('http', 'https'):
                return False
        except Exception:
            return False
        
        # Strict whitelist comparison
        return origin in self.allowed_origins
    
    def get_cors_headers(self, origin: str, request_method: str = 'GET') -> dict:
        """
        Get CORS headers for a response.
        Never reflects the origin - only returns whitelisted origins.
        """
        if not self.is_origin_allowed(origin):
            # Return minimal CORS headers for disallowed origins
            return {
                'Vary': 'Origin'
            }
        
        # Only allow specific methods
        allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        if request_method.upper() == 'OPTIONS':
            # Preflight request
            return {
                'Access-Control-Allow-Origin': origin,
                'Access-Control-Allow-Methods': ', '.join(allowed_methods),
                'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Max-Age': '3600',
                'Vary': 'Origin',
            }
        
        # Regular request
        return {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Expose-Headers': 'X-Request-Id',
            'Vary': 'Origin',
        }
    
    def get_cors_response(self, origin: str) -> dict:
        """
        Get complete CORS response headers for a request.
        This is the main entry point for middleware integration.
        """
        return self.get_cors_headers(origin)


# Flask integration example
def configure_cors(app, allowed_origins: Optional[List[str]] = None):
    """
    Configure Flask app with secure CORS settings.
    Apply this during app initialization.
    """
    cors_middleware = SecureCorsMiddleware(allowed_origins)
    
    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get('Origin', '')
        
        if origin:
            cors_headers = cors_middleware.get_cors_headers(origin, request.method)
            for key, value in cors_headers.items():
                response.headers[key] = value
        
        return response
    
    @app.route('/cors-config', methods=['GET'])
    def cors_config():
        """Return the allowed origins list (without credentials header)."""
        return {
            'allowed_origins': cors_middleware.allowed_origins,
            'note': 'CORS origins are strictly whitelisted. No origin reflection.'
        }
    
    return cors_middleware


# WSGI middleware integration
class CorsWsgiMiddleware:
    """
    WSGI middleware for secure CORS.
    Can be used with any WSGI-compatible framework.
    """
    
    def __init__(self, app, allowed_origins: Optional[List[str]] = None):
        self.app = app
        self.cors = SecureCorsMiddleware(allowed_origins)
    
    def __call__(self, environ, start_response):
        origin = environ.get('HTTP_ORIGIN', '')
        
        def cors_start_response(status, headers, exc_info=None):
            if origin:
                cors_headers = self.cors.get_cors_headers(
                    origin,
                    environ.get('REQUEST_METHOD', 'GET')
                )
                for key, value in cors_headers.items():
                    headers.append((key, value))
            return start_response(status, headers, exc_info)
        
        return self.app(environ, cors_start_response)


# Example: Fix for the existing API
def fix_cors_in_api(api_app):
    """
    Apply CORS fix to the existing API application.
    This function should be called during app initialization.
    """
    # The key fix: never use Access-Control-Allow-Origin: *
    # and never reflect the Origin header
    cors = SecureCorsMiddleware()
    
    @api_app.after_request
    def secure_cors(response):
        origin = request.headers.get('Origin', '')
        
        if origin:
            if cors.is_origin_allowed(origin):
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                response.headers['Vary'] = 'Origin'
            # If origin is not allowed, don't set Access-Control-Allow-Origin at all
            # This prevents the browser from exposing the response to JavaScript
        
        return response
    
    return cors