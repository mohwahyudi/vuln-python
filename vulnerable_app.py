#!/usr/bin/env python3

import os
import sqlite3
import subprocess
import pickle
import hashlib
import base64
from flask import Flask, request, render_template_string, redirect, session, jsonify
import xml.etree.ElementTree as ET
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_123"  # VULNERABILITY 1: Hardcoded Secret

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    ''')
    
    # Add default admin user if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        # VULNERABILITY 2: Storing plaintext passwords
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ('admin', 'admin123', 'admin'))
    conn.commit()
    conn.close()

init_db()

# Routes
@app.route('/')
def home():
    return render_template_string('''
    <h1>Welcome to the Vulnerable App</h1>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/search">Search</a></li>
        <li><a href="/profile">Profile</a></li>
        <li><a href="/admin">Admin Panel</a></li>
    </ul>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABILITY 3: SQL Injection
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            session['role'] = user[3]  # role
            return redirect('/profile')
        else:
            error = 'Invalid credentials'
    
    return render_template_string('''
    <h1>Login</h1>
    {% if error %}<p style="color: red;">{{ error }}</p>{% endif %}
    <form method="post">
        <label>Username: <input type="text" name="username"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <input type="submit" value="Login">
    </form>
    <p><a href="/">Back to Home</a></p>
    ''', error=error)

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect('/login')
    
    # VULNERABILITY 4: XSS (Cross-Site Scripting)
    username = session['username']
    return render_template_string('''
    <h1>Welcome, {{ username|safe }}</h1>
    <p>This is your profile page.</p>
    <p><a href="/logout">Logout</a></p>
    <p><a href="/">Back to Home</a></p>
    ''', username=username)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []
    
    if query:
        # VULNERABILITY 5: Command Injection
        try:
            cmd = f"grep -i {query} data.txt"
            output = subprocess.check_output(cmd, shell=True, text=True)
            results = output.splitlines()
        except subprocess.CalledProcessError:
            results = ["No results found or error occurred"]
    
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
    ''', query=query, results=results)

@app.route('/admin')
def admin():
    # VULNERABILITY 6: Broken Access Control
    # No proper authentication check for admin role
    if 'username' not in session:
        return redirect('/login')
    
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
def user_data():
    # VULNERABILITY 7: Insecure Deserialization
    serialized_data = request.args.get('data')
    if serialized_data:
        try:
            # Unsafe deserialization of user-provided data
            user_data = pickle.loads(base64.b64decode(serialized_data))
            return jsonify(user_data)
        except Exception as e:
            return jsonify({'error': str(e)})
    return jsonify({'error': 'No data provided'})

@app.route('/process_xml', methods=['POST'])
def process_xml():
    # VULNERABILITY 8: XML External Entity (XXE) Processing
    xml_data = request.data
    try:
        tree = ET.fromstring(xml_data)
        return jsonify({'result': 'XML processed successfully', 'root_tag': tree.tag})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABILITY 9: Weak Password Hashing
        # Using a weak hashing algorithm (MD5) without salt
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                          (username, password_hash, 'user'))
            conn.commit()
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
        <input type="submit" value="Register">
    </form>
    <p><a href="/">Back to Home</a></p>
    ''', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect('/')

@app.route('/download_log')
def download_log():
    # VULNERABILITY 10: Path Traversal
    filename = request.args.get('filename', 'app.log')
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    # Create a sample data file for the search function
    with open('data.txt', 'w') as f:
        f.write("This is sample data\nContains searchable content\nMore lines for testing\nSensitive information: password123")
    
    # VULNERABILITY 11: Insecure Configuration
    app.run(host='0.0.0.0', port=5000, debug=True)