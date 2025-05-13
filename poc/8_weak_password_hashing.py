#!/usr/bin/env python3

import requests
import sys
import hashlib
import sqlite3
import os
import time

def weak_password_hashing_poc(base_url):
    print("\n[*] Weak Password Hashing Proof of Concept")
    print("[*] This PoC demonstrates the risks of using weak hashing algorithms (MD5)")
    
    # The vulnerable endpoints
    register_url = f"{base_url}/register"
    login_url = f"{base_url}/login"
    
    # Create a user with a known password
    print("\n[+] Creating a user with a known password...")
    username = f"test_user_{int(time.time())}"
    password = "Password123!"
    
    register_data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(register_url, data=register_data)
    
    if "/login" in response.url:
        print(f"[+] Successfully registered user: {username}")
    else:
        print("[-] Failed to register user")
        print(f"[-] Response: {response.text[:100]}...")
        return
    
    # Verify we can login with this user
    print("\n[+] Verifying login works with the created user...")
    login_data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(login_url, data=login_data)
    
    if "/profile" in response.url:
        print("[+] Successfully logged in with the created user")
    else:
        print("[-] Failed to login with the created user")
        print(f"[-] Response: {response.text[:100]}...")
        return
    
    # Now, let's check if the application is using MD5 for password hashing
    # We need to access the database file directly for this part
    print("\n[+] Checking for weak password hashing...")
    
    # This part would typically be done by an attacker who has gained access to the database
    # For this PoC, we'll check if the database file exists in the current directory
    if os.path.exists("users.db"):
        print("[+] Found users database file")
        
        # Connect to the database and check the password hash
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result:
            stored_hash = result[0]
            print(f"[+] Retrieved password hash from database: {stored_hash}")
            
            # Check if it's an MD5 hash (32 characters, hexadecimal)
            if len(stored_hash) == 32 and all(c in "0123456789abcdef" for c in stored_hash.lower()):
                print("[!] WEAK PASSWORD HASHING VULNERABILITY CONFIRMED!")
                print("[+] The application appears to be using MD5 for password hashing")
                
                # Verify by computing the MD5 hash of the known password
                computed_md5 = hashlib.md5(password.encode()).hexdigest()
                print(f"[+] Computed MD5 hash of the password: {computed_md5}")
                
                if computed_md5 == stored_hash:
                    print("[!] Computed hash matches the stored hash - MD5 confirmed!")
                    
                    print("\n[+] Demonstrating the weakness of MD5:")
                    print("[+] 1. MD5 is fast to compute, making brute force attacks efficient")
                    
                    # Demonstrate how fast MD5 is
                    num_hashes = 1000000
                    start_time = time.time()
                    for _ in range(num_hashes):
                        hashlib.md5(password.encode()).hexdigest()
                    end_time = time.time()
                    
                    print(f"[+] Computed {num_hashes:,} MD5 hashes in {end_time - start_time:.2f} seconds")
                    print(f"[+] That's {num_hashes / (end_time - start_time):,.0f} hashes per second")
                    
                    print("\n[+] 2. MD5 has known collision vulnerabilities")
                    print("[+] 3. MD5 doesn't use salting in this implementation, making rainbow table attacks possible")
                    
                    print("\n[+] This vulnerability could allow attackers to:")
                    print("    1. Crack password hashes much more quickly")
                    print("    2. Use rainbow tables to find passwords without brute forcing")
                    print("    3. Identify users who share the same password (identical hashes)")
                else:
                    print("[-] Computed hash doesn't match stored hash - might not be using plain MD5")
                    print("[-] The application might be using a salt or a different algorithm")
            else:
                print("[-] The password hash doesn't appear to be MD5")
                print("[-] The application might be using a stronger hashing algorithm")
        else:
            print("[-] Couldn't find the user in the database")
        
        conn.close()
    else:
        print("[-] Couldn't access the database file directly")
        print("[+] In a real attack scenario, this would require gaining access to the database first")
        print("[+] Alternatively, an attacker might analyze the application code to identify the hashing method")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    weak_password_hashing_poc(base_url)