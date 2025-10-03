import os
import secrets
import ssl
import string
import io
import ipaddress
import socket
import base64
from threading import Thread
from typing import List, Optional, Any
import requests
import msal  # Keep Entra ID library but don't enable its login

# Third-party imports
import qrcode
from flask import (
    Flask, request, render_template_string, redirect,
    session, send_file, abort, Response
)
from gevent import pywsgi
from gevent import monkey
monkey.patch_all()

app = Flask(__name__)
app.secret_key = ''.join(
    secrets.choice(string.ascii_letters + string.digits)
    for _ in range(32)
)

# --------------------------
# Core Configuration
# --------------------------
BIND_ADDRESS = '0.0.0.0'
HTTPS_PORT = 8443
CERT_FILE = os.path.join(os.path.dirname(__file__), 'cert.pem')
KEY_FILE = os.path.join(os.path.dirname(__file__), 'key.pem')

# IP Whitelist Configuration
ALLOWED_IPS = [
    "127.0.0.1",    # Localhost
    "192.168.1.100" # Example trusted client
]

ALLOWED_SUBNETS = [
    "172.16.0.0/16", # Trusted subnet
    "10.0.0.0/24"    # Example subnet
]

# Intune Configuration
INTUNE_CLIENT_ID = os.environ.get('INTUNE_CLIENT_ID')
INTUNE_CLIENT_SECRET = os.environ.get('INTUNE_CLIENT_SECRET')
INTUNE_TENANT_ID = os.environ.get('INTUNE_TENANT_ID')

# Verify required files and configurations
if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
    raise FileNotFoundError("SSL certificate or key file missing")
if not all([INTUNE_CLIENT_ID, INTUNE_CLIENT_SECRET, INTUNE_TENANT_ID]):
    raise EnvironmentError("Incomplete Intune environment variable configuration")

# Global state - PIN recovery related variables
VALID_PIN = ""  # Generated at startup
ALLOWED_IP_OBJECTS = set()
ALLOWED_SUBNET_OBJECTS = set()

# Parse IP whitelist
try:
    ALLOWED_IP_OBJECTS = {ipaddress.ip_address(ip.strip()) for ip in ALLOWED_IPS}
    ALLOWED_SUBNET_OBJECTS = {
        ipaddress.ip_network(subnet.strip(), strict=False)
        for subnet in ALLOWED_SUBNETS
    }
except ValueError as e:
    raise ValueError(f"IP whitelist configuration error: {str(e)}") from e


# --------------------------
# PIN Authentication Core Functions
# --------------------------
def generate_pin() -> str:
    """Generate 6-digit numeric authentication PIN"""
    return ''.join(secrets.choice(string.digits) for _ in range(6))


@app.before_request
def enforce_security() -> None:
    """Security middleware: First verify IP whitelist, then verify PIN authentication status"""
    # 1. IP whitelist verification
    client_ip_str = request.remote_addr
    if not client_ip_str:
        abort(400, description="Unable to identify client IP")

    try:
        client_ip = ipaddress.ip_address(client_ip_str)
        if client_ip not in ALLOWED_IP_OBJECTS and not any(
            client_ip in subnet for subnet in ALLOWED_SUBNET_OBJECTS
        ):
            print(f"[Blocked] Unauthorized IP access: {client_ip_str}")
            abort(403, description="IP not in whitelist, access denied")
    except ValueError:
        abort(400, description="Invalid IP address format")

    # 2. PIN authentication verification (exclude static resource routes)
    if request.path.startswith('/qr/'):
        return
    if not session.get('authenticated') and request.path != '/':
        return redirect('/')


# --------------------------
# HTML Templates (PIN Login Page)
# --------------------------
HTML_PIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Enter Authentication PIN</title>
    <style>
        body { font-family: Segoe UI, Arial; margin: 40px; background: #f0f7ff; }
        .container { max-width: 400px; margin: 0 auto; padding: 25px;
                    background: white; border-radius: 10px; box-shadow: 0 0 15px #c0d8ff; }
        h1 { color: #1e5cb3; border-bottom: 2px solid #e6f0ff; padding-bottom: 10px; }
        .form-group { margin: 20px 0; }
        input[type="text"] { padding: 10px; width: 100%; border: 1px solid #c0d8ff;
                            border-radius: 5px; font-size: 16px; }
        button { background: #1e5cb3; color: white; border: none; padding: 12px 25px;
                border-radius: 5px; cursor: pointer; font-size: 16px; }
        .error { margin-top: 20px; padding: 15px; background: #ffebee;
                border-left: 4px solid #f44336; color: #d32f2f; }
        .hint { margin-top: 15px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>BitLocker Key Management System</h1>
        <h3>Please Enter Authentication PIN</h3>
        <form method="POST">
            <div class="form-group">
                <input type="text" name="pin" placeholder="6-digit PIN code" maxlength="6" required>
            </div>
            <button type="submit">Authenticate and Login</button>
        </form>
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        <div class="hint">Note: PIN code is provided by system administrator</div>
    </div>
</body>
</html>
'''

HTML_MAIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>BitLocker Key Management System (Intune)</title>
    <style>
        /* Keep original styles */
        body { font-family: Segoe UI, Arial; margin: 40px; background: #f0f7ff; }
        .container { max-width: 600px; margin: 0 auto; padding: 25px;
                    background: white; border-radius: 10px; box-shadow: 0 0 15px #c0d8ff; }
        /* Omitting some styles... */
        .auth-status { color: #28a745; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>BitLocker Key Management System</h1>
        <div class="auth-status">Authenticated via PIN</div>
        
        <form method="POST" onsubmit="return validateForm()">
            <div class="form-group">
                <input type="text" name="computer_name" placeholder="Enter device name" required>
                <p class="form-hint">Please enter full device name to query BitLocker recovery key</p>
            </div>
            <button type="submit">Get Recovery Key</button>
        </form>

        {% if result %}
            <div class="result {% if 'Error' in result or 'not found' in result %}error{% endif %}">
                {{ result }}
                {% if result_data %}
                    <ul>{% for key in result_data %}<li>{{ key }}</li>{% endfor %}</ul>
                {% endif %}
            </div>
        {% endif %}

        {% if qr_count > 0 %}
            <div class="qr-container">
                <h3>Recovery Key QR Code</h3>
                <img src="/qr/0" class="qr-image" alt="BitLocker recovery key QR code">
            </div>
        {% endif %}

        <div class="logout">
            <form method="POST" action="/logout">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>
    </div>
    <script>
        function validateForm() {
            const name = document.querySelector('input[name="computer_name"]').value.trim();
            if (!name) {
                alert('Please enter device name');
                return false;
            }
            return true;
        }
    </script>
</body>
</html>
'''


# --------------------------
# Core Functionality
# --------------------------
def generate_qr_code(data: str) -> io.BytesIO:
    """Generate QR code byte stream"""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        buffer = io.BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(buffer, 'PNG')
        buffer.seek(0)
        return buffer
    except Exception as e:
        print(f"QR code generation failed: {str(e)}")
        raise


def get_intune_access_token() -> Optional[str]:
    """Get Intune API access token"""
    try:
        token_url = f"https://login.microsoftonline.com/{INTUNE_TENANT_ID}/oauth2/v2.0/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": INTUNE_CLIENT_ID,
            "client_secret": INTUNE_CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default"
        }
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        return response.json().get("access_token")
    except Exception as e:
        print(f"Intune token acquisition failed: {str(e)}")
        return None


def get_bitlocker_key_from_intune(device_name: str, token: str) -> Optional[str]:
    """Retrieve BitLocker key from Intune"""
    try:
        url = "https://graph.microsoft.com/v1.0/deviceManagement/recoveryKeys"
        params = {"$filter": f"deviceName eq '{device_name}'"}
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        return data["value"][0].get("recoveryKey") if data.get("value") else None
    except Exception as e:
        print(f"Intune key query failed: {str(e)}")
        return None


# --------------------------
# Route Handling
# --------------------------
@app.route('/', methods=['GET', 'POST'])
def index() -> Response:
    """Main route: Handle PIN verification and key queries"""
    # Unauthenticated state: Handle PIN verification
    if not session.get('authenticated'):
        if request.method == 'POST':
            entered_pin = request.form.get('pin', '').strip()
            if entered_pin == VALID_PIN:
                session['authenticated'] = True
                session['qr_cache'] = []
                return redirect('/')
            return render_template_string(
                HTML_PIN_TEMPLATE, 
                error="Invalid PIN code, please try again"
            )
        return render_template_string(HTML_PIN_TEMPLATE, error=None)

    # Authenticated state: Handle key queries
    result = None
    result_data = None
    qr_cache = session.get('qr_cache', [])
    
    if request.method == 'POST':
        device_name = request.form.get('computer_name', '').strip()
        if not device_name:
            result = "Please enter device name"
        else:
            token = get_intune_access_token()
            if not token:
                result = "Unable to connect to Intune service, please check configuration"
            else:
                key = get_bitlocker_key_from_intune(device_name, token)
                if key:
                    result = f"Successfully retrieved BitLocker recovery key for device [{device_name}]"
                    result_data = [key]
                    # Generate and cache QR code
                    qr_buffer = generate_qr_code(key)
                    qr_cache = [base64.b64encode(qr_buffer.getvalue()).decode('utf-8')]
                    session['qr_cache'] = qr_cache
                else:
                    result = f"No BitLocker recovery key found for device [{device_name}]"

    return render_template_string(
        HTML_MAIN_TEMPLATE,
        result=result,
        result_data=result_data,
        qr_count=len(qr_cache)
    )


@app.route('/qr/<int:index>')
def qr_code(index: int) -> Response:
    """Serve QR code images"""
    if not session.get('authenticated'):
        return redirect('/')
    
    qr_cache = session.get('qr_cache', [])
    if 0 <= index < len(qr_cache):
        try:
            buffer = io.BytesIO(base64.b64decode(qr_cache[index]))
            return send_file(buffer, mimetype='image/png')
        except Exception as e:
            print(f"QR code loading failed: {str(e)}")
    return "QR code not found", 404


@app.route('/logout', methods=['POST'])
def logout() -> Response:
    """Logout functionality"""
    session.clear()
    return redirect('/')


# --------------------------
# Server Configuration
# --------------------------
def run_http_redirect() -> None:
    """HTTP to HTTPS redirection service"""
    def redirect_app(environ, start_response):
        host = environ.get('HTTP_HOST', 'localhost').split(':')[0]
        path = environ.get('PATH_INFO', '')
        url = f"https://{host}:{HTTPS_PORT}{path}"
        start_response('301 Moved Permanently', [('Location', url), ('Content-Length', '0')])
        return [b'']
    
    try:
        pywsgi.WSGIServer((BIND_ADDRESS, 80), redirect_app).serve_forever()
    except Exception as e:
        print(f"HTTP redirection service startup failed: {str(e)}")


def create_ssl_context() -> ssl.SSLContext:
    """Create secure SSL context"""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    )
    return context


# --------------------------
# Application Entry Point
# --------------------------
if __name__ == '__main__':
    # Generate and display PIN code
    VALID_PIN = generate_pin()
    print("\n===== AUTHENTICATION PIN =====")
    print(f"System generated PIN: {VALID_PIN}")
    print("Please use this PIN to log in to the system")
    print("==============================\n")

    # Start HTTP redirection service
    Thread(target=run_http_redirect, daemon=True).start()

    # Start HTTPS service
    try:
        ssl_context = create_ssl_context()
        server = pywsgi.WSGIServer(
            (BIND_ADDRESS, HTTPS_PORT),
            app,
            ssl_context=ssl_context
        )
        print(f"HTTPS service started: https://{socket.gethostbyname(socket.gethostname())}:{HTTPS_PORT}")
        server.serve_forever()
    except Exception as e:
        print(f"Service startup failed: {str(e)}")
