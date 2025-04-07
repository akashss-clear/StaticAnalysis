import os
import sqlite3
from flask import Flask, request, jsonify, render_template_string, redirect, session
import jwt
import subprocess
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Vulnerability 1: Injection (SQL Injection)
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Vulnerable SQL query (user input directly concatenated into SQL command)
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = cur.execute(query).fetchone()
    if result:
        return "Login Successful!"
    else:
        return "Invalid Credentials!", 401

# Vulnerability 2: Broken Authentication (Hardcoded credentials)
@app.route('/admin-login', methods=['POST'])
def admin_login():
    username = request.form['username']
    password = request.form['password']
    
    # Hardcoded credentials - an attacker can access them if exposed
    if username == 'admin' and password == 'password123':
        session['user'] = username
        return redirect('/admin-dashboard')
    
    return "Invalid credentials", 401

# Vulnerability 3: Sensitive Data Exposure
@app.route('/get-api-key', methods=['GET'])
def get_api_key():
    # Sensitive data is exposed in plaintext
    api_key = "hardcoded-api-key-123456"
    return jsonify({'api_key': api_key})

# Vulnerability 4: XML External Entity Injection (XXE)
@app.route('/parse-xml', methods=['POST'])
def parse_xml():
    from lxml import etree
    
    # Parsing XML with an unconfigured parser that allows external entity expansion
    xml_data = request.data
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(xml_data, parser=parser)
    
    return "XML parsed successfully!"

# Vulnerability 5: Security Misconfiguration
@app.route('/debug', methods=['GET'])
def debug_mode():
    # Debug mode enabled, which leaks sensitive stack trace info
    1 / 0  # Force an exception for testing purposes

# Vulnerability 6: Cross-Site Scripting (XSS)
@app.route('/greet', methods=['GET'])
def greet():
    # User input rendered without sanitization
    name = request.args.get('name', 'Guest')
    return render_template_string(f"<h1>Hello, {name}!</h1>")

# Vulnerability 7: Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize():
    import pickle
    
    # An attacker can send malicious serialized data to execute code on the server
    serialized_data = request.data
    obj = pickle.loads(serialized_data)  # Unsafe deserialization
    return f"Deserialized object: {obj}"

# Vulnerability 8: Using Components with Known Vulnerabilities
@app.route('/ping', methods=['GET'])
def ping():
    ip = request.args.get('ip')
    # Using subprocess without sanitizing inputs allows command injection
    result = subprocess.run(['ping', '-c', '4', ip], capture_output=True)
    return f"<pre>{result.stdout.decode()}</pre>"

# Vulnerability 9: Insufficient Logging and Monitoring
@app.route('/transfer', methods=['POST'])
def transfer():
    recipient = request.form['recipient']
    amount = request.form['amount']
    
    # No logs or monitoring in case of suspicious transaction
    # Sensitive actions are performed with no audits
    return f"Transferred {amount} to {recipient}"

# Vulnerability 10: Server-Side Request Forgery (SSRF)
@app.route('/fetch-url', methods=['GET'])
def fetch_url():
    import requests
    
    url = request.args.get('url')
    # Directly using user input as a URL, leading to SSRF attacks
    response = requests.get(url)
    return response.content

if __name__ == '__main__':
    app.run(debug=True)  # Debug, another potential vulnerability