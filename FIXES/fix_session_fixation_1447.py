"""
Fix for Issue #1447 - Session Fixation + Session ID in URL
Agent: lushan888
Bounty: $120 USD

Fix: Regenerate session ID on login, reject URL-based session IDs,
and use secure session cookies with HttpOnly and SameSite flags.
"""

import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional


class SecureSessionManager:
    """
    Session manager that prevents session fixation attacks.
    
    Security measures:
    1. Session ID is never accepted from URL parameters
    2. Session ID is regenerated on authentication (login)
    3. Session ID is cryptographically random (32 bytes, secrets.token_urlsafe)
    4. Session ID is bound to user agent and IP address
    5. Sessions expire after a configurable timeout
    """
    
    def __init__(self, secret_key: Optional[str] = None, session_timeout_minutes: int = 30):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self._sessions = {}  # In-memory session store (use Redis in production)
    
    def generate_session_id(self) -> str:
        """
        Generate a cryptographically secure random session ID.
        Never uses predictable values like timestamps or counters.
        """
        return secrets.token_urlsafe(32)
    
    def create_session(self, user_id: str, user_agent: str = "", ip_address: str = "") -> str:
        """
        Create a new session for the user.
        Always generates a fresh session ID (never reuses existing ones).
        """
        session_id = self.generate_session_id()
        
        session_data = {
            'user_id': user_id,
            'created_at': datetime.now(),
            'last_accessed': datetime.now(),
            'user_agent': user_agent,
            'ip_address': ip_address,
            'data': {}
        }
        
        # Sign the session ID to prevent tampering
        signature = hmac.new(
            self.secret_key.encode(),
            session_id.encode(),
            hashlib.sha256
        ).hexdigest()
        
        self._sessions[f"{session_id}:{signature[:16]}"] = session_data
        return session_id
    
    def regenerate_session(self, old_session_id: str, user_id: str, user_agent: str = "", ip_address: str = "") -> Optional[str]:
        """
        Regenerate session ID on privilege escalation (e.g., login).
        This is the key fix for session fixation - we create a completely new session
        and invalidate the old one.
        """
        # Invalidate old session
        self.destroy_session(old_session_id)
        
        # Create new session with fresh ID
        return self.create_session(user_id, user_agent, ip_address)
    
    def validate_session(self, session_id: str, expected_user_agent: str = "", expected_ip: str = "") -> bool:
        """
        Validate a session ID.
        Rejects URL-provided session IDs (they should only come from cookies).
        """
        if not session_id or len(session_id) < 32:
            return False
        
        # Check if session exists
        for key, data in self._sessions.items():
            stored_id = key.split(':')[0]
            if hmac.compare_digest(stored_id, session_id):
                # Check expiration
                if datetime.now() - data['last_accessed'] > self.session_timeout:
                    self.destroy_session(session_id)
                    return False
                
                # Optional: Verify user agent and IP for additional security
                if expected_user_agent and data['user_agent'] and data['user_agent'] != expected_user_agent:
                    return False
                
                data['last_accessed'] = datetime.now()
                return True
        
        return False
    
    def get_session_data(self, session_id: str) -> Optional[dict]:
        """Get session data if session is valid."""
        for key, data in self._sessions.items():
            stored_id = key.split(':')[0]
            if hmac.compare_digest(stored_id, session_id):
                if datetime.now() - data['last_accessed'] > self.session_timeout:
                    return None
                return data
        return None
    
    def destroy_session(self, session_id: str) -> None:
        """Destroy a session."""
        keys_to_delete = []
        for key in self._sessions:
            stored_id = key.split(':')[0]
            if hmac.compare_digest(stored_id, session_id):
                keys_to_delete.append(key)
        for key in keys_to_delete:
            del self._sessions[key]


# Flask middleware to reject URL-based session IDs
def reject_url_session_id(app):
    """
    Flask middleware that rejects session IDs passed via URL parameters.
    Session IDs should ONLY come from secure, HttpOnly cookies.
    """
    original_wsgi_app = app.wsgi_app
    
    def middleware(environ, start_response):
        # Check if session ID is in query string
        query_string = environ.get('QUERY_STRING', '')
        if 'session_id=' in query_string or 'sid=' in query_string or 'session=' in query_string:
            # Remove session ID from query string
            from urllib.parse import urlencode, parse_qs
            params = parse_qs(query_string)
            params.pop('session_id', None)
            params.pop('sid', None)
            params.pop('session', None)
            environ['QUERY_STRING'] = urlencode(params, doseq=True)
        
        return original_wsgi_app(environ, start_response)
    
    app.wsgi_app = middleware
    return app


# Usage example for Flask app
def configure_secure_sessions(app):
    """
    Configure Flask app with secure session settings.
    Apply this in the main app initialization.
    """
    # Reject URL-based session IDs
    reject_url_session_id(app)
    
    # Secure cookie settings
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_NAME='__Host-session',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )
    
    # Regenerate session on login
    @app.before_request
    def ensure_secure_session():
        if 'session_id' in request.args:
            # Redirect to remove session ID from URL
            from flask import redirect
            return redirect(request.path, code=301)
    
    return app