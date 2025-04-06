AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Secure version that prevents XSS
from flask import Flask, request, escape

app = Flask(__name__)

@app.route("/")
def index():
    # Get and sanitize input
    name = request.args.get("name", "Guest")
    safe_name = escape(name)  # Escape any dangerous characters
    
    # Render sanitized input into the page
    return f"<h1>Welcome, {safe_name}</h1>"  # Safe from XSS!

# Run the web application
if __name__ == "__main__":
    app.run(debug=True)