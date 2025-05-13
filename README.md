# Security Vulnerabilities Demo

This repository contains a deliberately vulnerable Python Flask web application and its secure counterpart. The purpose is to demonstrate common security vulnerabilities, explain them, and show how to fix them.

## Overview

This project was created as an educational resource to help developers understand common security vulnerabilities and how to mitigate them. It includes:

1. A vulnerable Flask application demonstrating multiple security issues
2. A secure version of the same application with all vulnerabilities fixed
3. Detailed explanations of each vulnerability and its fix
4. Docker configuration for easy deployment
5. Testing scripts to demonstrate the vulnerabilities

## Vulnerabilities Demonstrated

The application demonstrates the following vulnerabilities:

1. **Hardcoded Secrets**: Sensitive information embedded in source code
2. **Insecure Password Storage**: Storing passwords in plaintext or with weak hashing
3. **SQL Injection**: Unsanitized user input in database queries
4. **Cross-Site Scripting (XSS)**: Unescaped user input rendered in HTML
5. **Command Injection**: Unsanitized user input passed to system commands
6. **Broken Access Control**: Insufficient authorization checks
7. **Insecure Deserialization**: Unsafe deserialization of user-provided data
8. **XML External Entity (XXE) Processing**: Unsafe parsing of XML input
9. **Weak Password Hashing**: Using inadequate algorithms for password storage
10. **Path Traversal**: Insufficient validation of file paths
11. **Insecure Configuration**: Dangerous settings in production environments

## Getting Started

### Prerequisites

- Python 3.7 or higher
- Docker and Docker Compose (optional, for containerized deployment)

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/mohwahyudi/vuln-python.git
   cd vuln-python
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Applications

#### Option 1: Using the run script

**On Linux/macOS:**
```bash
chmod +x run.sh
./run.sh
```

**On Windows:**
```cmd
run.bat
```

These scripts provide a menu to run either the vulnerable app, secure app, or both using Docker.

#### Option 2: Running directly

##### Running the Vulnerable App

```bash
python vulnerable_app.py
```

The vulnerable application will be available at http://localhost:5000

##### Running the Secure App

```bash
python secure_app.py
```

The secure application will be available at http://localhost:5000

#### Option 3: Using Docker Compose

```bash
docker-compose up --build
```

This will start both applications:
- Vulnerable app at http://localhost:5000
- Secure app at http://localhost:5001

### Testing the Vulnerabilities

#### Basic Testing

You can use the included test script to demonstrate the vulnerabilities:

```bash
python test_vulnerabilities.py http://localhost:5000  # For the vulnerable app
python test_vulnerabilities.py http://localhost:5001  # For the secure app
```

#### Advanced Testing with Proof of Concept Scripts

For more realistic exploitation scenarios, use the PoC scripts [under development]:

```bash
# Run a specific PoC
python poc/1_sql_injection.py http://localhost:5000

# Run all PoCs
python poc/run_all_pocs.py http://localhost:5000
```

These PoC scripts demonstrate how the vulnerabilities could be exploited in real-world scenarios and explain the potential impact of each vulnerability.

