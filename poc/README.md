# Security Vulnerability Proof of Concept (PoC) Scripts

This directory contains proof of concept scripts that demonstrate how the vulnerabilities in the vulnerable application can be exploited in a real-world scenario.

## Warning

**These scripts are for educational purposes only.** They demonstrate security vulnerabilities and how they can be exploited. Using these scripts against systems without explicit permission is illegal and unethical.

## Available PoCs

1. **SQL Injection** (`1_sql_injection.py`): Demonstrates how to bypass authentication using SQL injection
2. **Cross-Site Scripting (XSS)** (`2_xss.py`): Shows how stored XSS can be used to execute JavaScript in a victim's browser
3. **Command Injection** (`3_command_injection.py`): Executes arbitrary OS commands through the search function
4. **Path Traversal** (`4_path_traversal.py`): Accesses files outside the intended directory
5. **Insecure Deserialization** (`5_insecure_deserialization.py`): Achieves remote code execution via pickle deserialization
6. **XML External Entity (XXE)** (`6_xxe.py`): Reads local files and performs SSRF via XXE
7. **Broken Access Control** (`7_broken_access_control.py`): Accesses admin functionality as a regular user
8. **Weak Password Hashing** (`8_weak_password_hashing.py`): Demonstrates the weakness of MD5 hashing
9. **Hardcoded Secrets** (`9_hardcoded_secrets.py`): Forges session cookies using a hardcoded secret key
10. **Insecure Configuration** (`10_insecure_configuration.py`): Exploits debug mode and other insecure settings

## Usage

### Running Individual PoCs

To run an individual PoC script:

```bash
python 1_sql_injection.py http://localhost:5000
```

Replace `1_sql_injection.py` with the script you want to run and `http://localhost:5000` with the URL of the vulnerable application.

### Running All PoCs

To run all PoC scripts in sequence:

```bash
python run_all_pocs.py http://localhost:5000
```

## Understanding the PoCs

Each PoC script follows a similar structure:

1. It first explains what vulnerability it's demonstrating
2. It attempts to verify if the vulnerability exists
3. It exploits the vulnerability to show its impact
4. It explains the potential consequences of the vulnerability

The scripts include detailed comments explaining what's happening at each step.

## Mitigation

To understand how to fix these vulnerabilities, refer to the secure version of the application (`secure_app.py`) and the detailed explanations in the main README file.

## Ethical Considerations

These scripts are designed to be non-destructive and only demonstrate the vulnerabilities without causing harm. However, in a real attack scenario, these vulnerabilities could be exploited in more damaging ways.

Always practice security testing ethically and legally, with proper authorization.