#!/usr/bin/env python3

import requests
import sys
import socket
import json
import re

def insecure_configuration_poc(base_url):
    print("\n[*] Insecure Configuration Proof of Concept")
    print("[*] This PoC demonstrates the risks of insecure application configuration")
    
    # Extract the host and port from the base URL
    from urllib.parse import urlparse
    parsed_url = urlparse(base_url)
    host = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    
    # Check if debug mode is enabled
    print("\n[+] Checking if Flask debug mode is enabled...")
    
    # Try to trigger a deliberate error to see if we get a debug traceback
    response = requests.get(f"{base_url}/non_existent_endpoint_12345")
    
    if response.status_code == 404 and "Werkzeug" in response.text and "Debugger" in response.text:
        print("[!] INSECURE CONFIGURATION VULNERABILITY CONFIRMED!")
        print("[+] Flask debug mode is enabled in production!")
        
        # Extract the traceback information
        if "Traceback" in response.text:
            print("\n[+] Server error traceback exposed:")
            traceback_match = re.search(r'<pre class="traceback">(.+?)</pre>', response.text, re.DOTALL)
            if traceback_match:
                traceback_lines = traceback_match.group(1).strip().split('\n')[:5]  # First 5 lines
                for line in traceback_lines:
                    print(f"    {line.strip()}")
                print("    ...")
        
        # Check if the Werkzeug debugger console is available
        console_pattern = re.search(r'<form action="[^"]*console"', response.text)
        if console_pattern:
            print("\n[!] Werkzeug interactive debugger console is available!")
            print("[+] This allows arbitrary code execution on the server")
            
            # In a real attack, one could extract the PIN and use it to access the console
            # We won't demonstrate the actual code execution for safety reasons
            print("[+] An attacker could:")
            print("    1. Extract the debugger PIN from the server environment")
            print("    2. Access the interactive Python console")
            print("    3. Execute arbitrary code with the permissions of the web server process")
    else:
        print("[-] Flask debug mode doesn't appear to be enabled")
    
    # Check if the application is binding to all network interfaces (0.0.0.0)
    print("\n[+] Checking if the application is binding to all network interfaces...")
    
    # This check is more theoretical as we can't directly determine this from HTTP requests
    # In a real scenario, this would be verified by checking if the app is accessible from external IPs
    print("[+] Testing if the application is accessible from multiple network routes...")
    
    accessible_routes = []
    try:
        # Try connecting to localhost
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex(('localhost', port))
        if result == 0:
            accessible_routes.append('localhost')
        s.close()
        
        # Try connecting to 127.0.0.1
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex(('127.0.0.1', port))
        if result == 0:
            accessible_routes.append('127.0.0.1')
        s.close()
        
        # Try connecting to the machine's actual IP address
        # This is a simplified check and might not work in all environments
        if host not in ['localhost', '127.0.0.1']:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                accessible_routes.append(host)
            s.close()
        
        if len(accessible_routes) > 1:
            print(f"[+] Application is accessible via multiple routes: {', '.join(accessible_routes)}")
            print("[+] This suggests the application might be binding to all interfaces (0.0.0.0)")
            print("[!] This is potentially insecure in a production environment")
        else:
            print(f"[+] Application appears to be accessible only via: {', '.join(accessible_routes)}")
    except Exception as e:
        print(f"[-] Error during network testing: {e}")
    
    # Check for information disclosure in HTTP headers
    print("\n[+] Checking for information disclosure in HTTP headers...")
    
    response = requests.get(base_url)
    headers = response.headers
    
    sensitive_headers = {
        'Server': headers.get('Server'),
        'X-Powered-By': headers.get('X-Powered-By'),
        'X-AspNet-Version': headers.get('X-AspNet-Version'),
        'X-Runtime': headers.get('X-Runtime')
    }
    
    disclosed_info = {k: v for k, v in sensitive_headers.items() if v is not None}
    
    if disclosed_info:
        print("[+] Found potentially sensitive information in HTTP headers:")
        for header, value in disclosed_info.items():
            print(f"    {header}: {value}")
        print("[+] This information could help attackers fingerprint the application stack")
    else:
        print("[+] No obvious information disclosure in HTTP headers")
    
    # Summary of findings
    print("\n[+] Insecure configuration risks:")
    print("    1. Debug mode in production can expose sensitive information and allow code execution")
    print("    2. Binding to all interfaces (0.0.0.0) exposes the application unnecessarily")
    print("    3. Verbose error messages can leak implementation details")
    print("    4. Information disclosure in HTTP headers helps attackers profile the application")
    print("    5. Default or weak credentials for administrative interfaces")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    insecure_configuration_poc(base_url)