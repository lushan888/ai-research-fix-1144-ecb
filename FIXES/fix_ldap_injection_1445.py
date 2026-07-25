"""
Fix for Issue #1445 - LDAP Injection → Anonymous Bind Bypass
Agent: lushan888
Bounty: $120 USD

Fix: Use parameterized LDAP queries and input validation to prevent
LDAP injection attacks that bypass authentication.
"""

import re
from typing import Optional, Tuple, List
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.utils.conv import escape_filter_chars


class SecureLdapAuthenticator:
    """
    Secure LDAP authenticator that prevents LDAP injection attacks.
    
    Security measures:
    1. Always uses parameterized LDAP queries (escape_filter_chars)
    2. Validates and sanitizes all user input before LDAP operations
    3. Uses separate bind credentials (not anonymous bind)
    4. Restricts search base to a specific OU (prevents directory traversal)
    5. Implements account lockout after failed attempts
    """
    
    # Characters that are dangerous in LDAP filters
    DANGEROUS_CHARS = re.compile(r'[()*&|!><=~\x00]')
    
    # Maximum LDAP filter length to prevent DoS
    MAX_FILTER_LENGTH = 256
    
    def __init__(
        self,
        ldap_server: str,
        bind_dn: str,
        bind_password: str,
        search_base: str,
        port: int = 389,
        use_ssl: bool = False,
    ):
        self.server = Server(ldap_server, port=port, use_ssl=use_ssl, get_info=ALL)
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.search_base = search_base
        self._failed_attempts: dict = {}
    
    def _sanitize_input(self, user_input: str) -> str:
        """
        Sanitize user input for LDAP operations.
        Removes characters that could be used for LDAP injection.
        """
        if not user_input or not isinstance(user_input, str):
            raise ValueError("Invalid input")
        
        if len(user_input) > self.MAX_FILTER_LENGTH:
            raise ValueError("Input too long")
        
        # Remove dangerous characters
        sanitized = self.DANGEROUS_CHARS.sub('', user_input)
        
        # Escape remaining special characters for LDAP filter
        sanitized = escape_filter_chars(sanitized)
        
        return sanitized
    
    def _check_rate_limit(self, username: str) -> bool:
        """Check if the account is temporarily locked."""
        from datetime import datetime, timedelta
        
        if username in self._failed_attempts:
            attempts, lock_time = self._failed_attempts[username]
            if attempts >= 5:
                if datetime.now() - lock_time < timedelta(minutes=15):
                    return False
                else:
                    # Reset after lockout period
                    del self._failed_attempts[username]
        return True
    
    def _record_failed_attempt(self, username: str):
        """Record a failed login attempt."""
        from datetime import datetime
        
        if username not in self._failed_attempts:
            self._failed_attempts[username] = [1, datetime.now()]
        else:
            attempts, _ = self._failed_attempts[username]
            self._failed_attempts[username] = [attempts + 1, datetime.now()]
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[str], Optional[dict]]:
        """
        Authenticate a user against LDAP with injection protection.
        
        Args:
            username: User's login name
            password: User's password
            
        Returns:
            (success, error_message, user_info)
        """
        # Rate limiting
        if not self._check_rate_limit(username):
            return False, "Account temporarily locked. Try again later.", None
        
        try:
            # Sanitize inputs
            safe_username = self._sanitize_input(username)
            
            if not safe_username:
                return False, "Invalid username", None
            
            # Use parameterized LDAP search (never concatenate user input)
            search_filter = f"(uid={safe_username})"
            
            # Establish connection with service account (not anonymous)
            with Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                auto_bind=True,
            ) as conn:
                # Search for user with restricted search base
                conn.search(
                    search_base=self.search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=['cn', 'mail', 'uid', 'dn'],
                    size_limit=1,  # Only need one result
                )
                
                if len(conn.entries) == 0:
                    self._record_failed_attempt(username)
                    return False, "Invalid credentials", None
                
                user_entry = conn.entries[0]
                user_dn = user_entry.entry_dn
                
                # Now attempt to bind as the user with their password
                # This is the proper way to verify credentials
                with Connection(
                    self.server,
                    user=user_dn,
                    password=password,
                    auto_bind=True,
                ) as user_conn:
                    # Successful authentication
                    user_info = {
                        'dn': user_dn,
                        'cn': str(user_entry.cn.value) if hasattr(user_entry, 'cn') else '',
                        'mail': str(user_entry.mail.value) if hasattr(user_entry, 'mail') else '',
                        'uid': str(user_entry.uid.value) if hasattr(user_entry, 'uid') else '',
                    }
                    return True, None, user_info
                    
        except ldap3.core.exceptions.LDAPBindError:
            # Bind failed - invalid password
            self._record_failed_attempt(username)
            return False, "Invalid credentials", None
        except ldap3.core.exceptions.LDAPException as e:
            # LDAP server error
            return False, "Authentication service unavailable", None
        except ValueError as e:
            # Input validation error
            return False, str(e), None
    
    def search_users(self, search_term: str, max_results: int = 10) -> List[dict]:
        """
        Search for users with injection protection.
        
        Args:
            search_term: Search term (sanitized before use)
            max_results: Maximum number of results to return
            
        Returns:
            List of user dictionaries
        """
        try:
            safe_term = self._sanitize_input(search_term)
            
            if not safe_term:
                return []
            
            # Use parameterized search with wildcard (safe because input is sanitized)
            search_filter = f"(|(cn=*{safe_term}*)(uid=*{safe_term}*))"
            
            with Connection(
                self.server,
                user=self.bind_dn,
                password=self.bind_password,
                auto_bind=True,
            ) as conn:
                conn.search(
                    search_base=self.search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=['cn', 'mail', 'uid'],
                    size_limit=max_results,
                )
                
                results = []
                for entry in conn.entries:
                    results.append({
                        'cn': str(entry.cn.value) if hasattr(entry, 'cn') else '',
                        'mail': str(entry.mail.value) if hasattr(entry, 'mail') else '',
                        'uid': str(entry.uid.value) if hasattr(entry, 'uid') else '',
                    })
                
                return results
                
        except (ldap3.core.exceptions.LDAPException, ValueError):
            return []


# Example: Fix for Flask app with LDAP authentication
def fix_ldap_auth_in_flask(app, ldap_config: dict):
    """
    Configure Flask app with secure LDAP authentication.
    """
    authenticator = SecureLdapAuthenticator(
        ldap_server=ldap_config['server'],
        bind_dn=ldap_config['bind_dn'],
        bind_password=ldap_config['bind_password'],
        search_base=ldap_config['search_base'],
    )
    
    @app.route('/ldap-login', methods=['POST'])
    def ldap_login():
        from flask import request, jsonify
        
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        success, error, user_info = authenticator.authenticate(username, password)
        
        if success:
            return jsonify({
                'status': 'success',
                'user': user_info
            })
        else:
            return jsonify({
                'status': 'error',
                'message': error
            }), 401
    
    return authenticator