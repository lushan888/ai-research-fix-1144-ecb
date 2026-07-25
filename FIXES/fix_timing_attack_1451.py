"""
Fix for Issue #1451 - Timing Attack on Password Verification → User Enumeration
Agent: lushan888
Bounty: $120 USD

Fix: Constant-time password comparison and uniform response timing
to prevent user enumeration via timing side-channel.
"""

import hmac
import time
import hashlib


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.
    Uses HMAC comparison to ensure execution time is independent of input.
    """
    return hmac.compare_digest(a.encode(), b.encode())


def verify_password_constant_time(input_password: str, stored_hash: str, stored_salt: str) -> bool:
    """
    Verify password using constant-time comparison.
    The hash computation and comparison always take the same amount of time
    regardless of whether the user exists or the password is correct.
    """
    # Compute hash of input password with stored salt
    input_hash = hashlib.pbkdf2_hmac(
        'sha256',
        input_password.encode(),
        stored_salt.encode(),
        100000  # Fixed iteration count to prevent timing variance
    ).hex()
    
    # Constant-time comparison
    return constant_time_compare(input_hash, stored_hash)


def secure_login(username: str, password: str, user_db: dict) -> dict:
    """
    Secure login with constant-time response.
    Prevents user enumeration by ensuring identical response timing
    regardless of whether the username exists.
    """
    start_time = time.time()
    
    # Fixed dummy hash for non-existent users (prevents timing leak)
    DUMMY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    DUMMY_SALT = "00000000000000000000000000000000"
    
    # Look up user - timing of this is negligible compared to hash comparison
    user = user_db.get(username)
    
    # Always compute hash comparison, even for non-existent users
    stored_hash = user['password_hash'] if user else DUMMY_HASH
    stored_salt = user['salt'] if user else DUMMY_SALT
    
    password_valid = verify_password_constant_time(password, stored_hash, stored_salt)
    
    # Add fixed delay to mask any remaining timing variance
    elapsed = (time.time() - start_time) * 1000
    min_delay = 50  # 50ms minimum response time
    if elapsed < min_delay:
        time.sleep((min_delay - elapsed) / 1000.0)
    
    if not user:
        return {"success": False, "error": "Invalid credentials", "timing_ms": min_delay}
    
    if not password_valid:
        return {"success": False, "error": "Invalid credentials", "timing_ms": min_delay}
    
    return {"success": True, "user": username, "timing_ms": min_delay}