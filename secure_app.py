#!/usr/bin/env python3

import os
import sqlite3
import subprocess
import json
import hashlib
import secrets
import base64
from flask import Flask, request, render_template_string, redirect, session, jsonify, escape
import defusedxml.ElementTree as safe_ET
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import re
from functools import wraps

# Configure secure logging (avoid logging sensitive information)
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filename='app.log')
logger = logging.getLogger(__name__)

app = Flask(__name__)
# FIX 1: Use environment variable for secret key or generate a strong random one
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Database setup with parameterized queries
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        salt TEXT
    )
    ''')
    
    # Add default admin user if not exists
    cursor.execute("SELECT * FROM users WHERE username = ?",("admin",))
    if not cursor.fetchone():
        # FIX 2: Use strong password hashing with salt
        admin_password = os.environ.get('ADMIN_PASSWORD') or 'StrongAdminPass!123'
        password_hash = generate_password_hash(admin_password)
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ('admin', password_hash, 'admin'))
    conn.commit()
    conn.close()

init_db()

# Security helper functions
def is_admin():
    return session.get('role') == 'admin'

# Decorator for requiring authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Decorator for requiring admin role
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            return "Unauthorized", 403
        return f(*args, **kwargs)
    return decorated_function

# Input validation
def is_safe_input(input_string):
    # Basic input validation - allow alphanumeric and some special chars
    pattern = re.compile(r'^[a-zA-Z0-9_\-\.\s]+$')
    return bool(pattern.match(input_string))

# Routes
@app.route('/')
def home():
    return render_template_string('''
    <h1>Welcome to the Secure App</h1>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/register">Register</a></li>
        <li><a href="/search">Search</a></li>
        <li><a href="/profile">Profile</a></li>
        {% if session.get('role') == 'admin' %}
        <li><a href="/admin">Admin Panel</a></li>
        {% endif %}
    </ul>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # FIX 3: Use parameterized queries to prevent SQL injection
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):  # Verify password hash
            session['username'] = username
            session['role'] = user[3]  # role
            logger.info(f"User logged in: {username}")
            return redirect('/profile')
        else:
            error = 'Invalid credentials'
            logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template_string('''
    <h1>Login</h1>
    {% if error %}<p style="color: red;">{{ error }}</p>{% endif %}
    <form method="post">
        <label>Username: <input type="text" name="username"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <input type="submit" value="Login">
    </form>
    <p><a href="/register">Register</a></p>
    <p><a href="/">Back to Home</a></p>
    ''', error=error)

@app.route('/profile')
@login_required
def profile():
    # FIX 4: Prevent XSS by escaping user input
    username = escape(session['username'])
    return render_template_string('''
    <h1>Welcome, {{ username }}</h1>
    <p>This is your profile page.</p>
    <p><a href="/logout">Logout</a></p>
    <p><a href="/">Back to Home</a></p>
    ''', username=username)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    results = []
    
    if query:
        # FIX 5: Prevent command injection by using a safe alternative
        # Instead of using shell commands, use Python's built-in functions
        try:
            if not is_safe_input(query):
                results = ["Invalid search query"]
            else:
                with open('data.txt', 'r') as f:
                    lines = f.readlines()
                results = [line.strip() for line in lines if query.lower() in line.lower()]
                if not results:
                    results = ["No results found"]
        except Exception as e:
            logger.error(f"Search error: {str(e)}")
            results = ["An error occurred during search"]
    
    return render_template_string('''
    <h1>Search</h1>
    <form method="get">
        <input type="text" name="q" value="{{ query }}">
        <input type="submit" value="Search">
    </form>
    <h2>Results:</h2>
    <ul>
    {% for result in results %}
        <li>{{ result }}</li>
    {% endfor %}
    </ul>
    <p><a href="/">Back to Home</a></p>
    ''', query=escape(query), results=results)

@app.route('/admin')
@login_required
@admin_required  # FIX 6: Proper access control with role check
def admin():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return render_template_string('''
    <h1>Admin Panel</h1>
    <h2>Users:</h2>
    <ul>
    {% for user in users %}
        <li>ID: {{ user[0] }}, Username: {{ user[1] }}, Role: {{ user[2] }}</li>
    {% endfor %}
    </ul>
    <p><a href="/">Back to Home</a></p>
    ''', users=users)

@app.route('/api/user_data')
@login_required
def user_data():
    # FIX 7: Avoid insecure deserialization, use safe alternatives like JSON
    serialized_data = request.args.get('data')
    if serialized_data:
        try:
            # Use JSON instead of pickle for serialization/deserialization
            user_data = json.loads(base64.b64decode(serialized_data))
            return jsonify(user_data)
        except Exception as e:
            logger.error(f"Data parsing error: {str(e)}")
            return jsonify({'error': 'Invalid data format'})
    return jsonify({'error': 'No data provided'})

@app.route('/process_xml', methods=['POST'])
@login_required
def process_xml():
    # FIX 8: Use defusedxml to prevent XXE attacks
    xml_data = request.data
    try:
        tree = safe_ET.fromstring(xml_data)
        return jsonify({'result': 'XML processed successfully', 'root_tag': tree.tag})
    except Exception as e:
        logger.error(f"XML processing error: {str(e)}")
        return jsonify({'error': 'Invalid XML format'})

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate password strength
        if len(password) < 8:
            error = "Password must be at least 8 characters long"
        elif not re.search(r'[A-Z]', password):
            error = "Password must contain at least one uppercase letter"
        elif not re.search(r'[a-z]', password):
            error = "Password must contain at least one lowercase letter"
        elif not re.search(r'[0-9]', password):
            error = "Password must contain at least one number"
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            error = "Password must contain at least one special character"
        else:
            # FIX 9: Use strong password hashing with Werkzeug
            password_hash = generate_password_hash(password)
            
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                              (username, password_hash, 'user'))
                conn.commit()
                logger.info(f"New user registered: {username}")
                return redirect('/login')
            except sqlite3.IntegrityError:
                error = "Username already exists"
            finally:
                conn.close()
    
    return render_template_string('''
    <h1>Register</h1>
    {% if error %}<p style="color: red;">{{ error }}</p>{% endif %}
    <form method="post">
        <label>Username: <input type="text" name="username"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <p>Password must be at least 8 characters and include uppercase, lowercase, numbers, and special characters.</p>
        <input type="submit" value="Register">
    </form>
    <p><a href="/">Back to Home</a></p>
    ''', error=error)

@app.route('/logout')
def logout():
    username = session.get('username')
    session.clear()  # Clear the entire session
    if username:
        logger.info(f"User logged out: {username}")
    return redirect('/')

@app.route('/download_log')
@login_required
@admin_required
def download_log():
    # FIX 10: Prevent path traversal by validating and sanitizing input
    filename = request.args.get('filename', 'app.log')
    
    # Restrict to only specific allowed files
    allowed_files = {'app.log', 'error.log'}
    if filename not in allowed_files:
        logger.warning(f"Attempted unauthorized file access: {filename}")
        return "Access denied", 403
    
    # Use os.path.join and abspath to ensure the path is within the allowed directory
    safe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), filename))
    base_dir = os.path.abspath(os.path.dirname(__file__))
    
    if not safe_path.startswith(base_dir):
        logger.warning(f"Path traversal attempt: {filename}")
        return "Access denied", 403
    
    try:
        with open(safe_path, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        logger.error(f"Log access error: {str(e)}")
        return f"Error: {str(e)}"

if __name__ == '__main__':
    # Create a sample data file for the search function
    with open('data.txt', 'w') as f:
        f.write("This is sample data\nContains searchable content\nMore lines for testing\nSensitive information: [REDACTED]")
    
    # FIX 11: Secure configuration
    # In production, set debug=False and use a proper WSGI server
    is_production = os.environ.get('PRODUCTION', 'False').lower() == 'true'
    if is_production:
        app.run(host='127.0.0.1', port=5000, debug=False)
    else:
        # For development only
        app.run(host='127.0.0.1', port=5000, debug=True)