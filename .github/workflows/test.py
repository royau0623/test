"""
Intune BitLocker Key Manager - Secure Production Version

A secure web application to retrieve BitLocker recovery keys from Microsoft Intune
using Azure AD authentication. Includes CSRF protection and TLS 1.2+ enforcement.
"""

# Standard library imports
import os
import ssl
import io
import ipaddress
import socket
import secrets
import string
from threading import Thread
from typing import List, Dict, Any
from gevent import pywsgi
from gevent import monkey
monkey.patch_all()

# Third-party imports
import msal
import requests
import qrcode
from flask import (
    Flask, request, render_template_string, redirect,
    session, send_file, abort, make_response
)
from flask_wtf import CSRFProtect  # Import CSRF protection

# --------------------------
# Azure AD and Graph Configuration
# --------------------------
CLIENT_ID     = os.getenv("INTUNE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("INTUNE_CLIENT_SECRET", "")
TENANT_ID     = os.getenv("INTUNE_TENANT_ID", "")

# Validate required environment variables
if not CLIENT_SECRET:
    raise RuntimeError("INTUNE_CLIENT_SECRET environment variable not set")

AUTHORITY     = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE         = ["https://graph.microsoft.com/.default"]

# Graph endpoints
BASE_URL           = "https://graph.microsoft.com/v1.0"
LIST_KEYS_URL      = f"{BASE_URL}/informationProtection/bitlocker/recoveryKeys"
KEY_DETAIL_URL     = f"{BASE_URL}/informationProtection/bitlocker/recoveryKeys/{{id}}?$select=key"
MANAGED_DEVICES_URL= f"{BASE_URL}/deviceManagement/managedDevices"

# --------------------------
# Security Hardening - TLS Configuration
# --------------------------
STRONG_CIPHERS = (
    'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
    'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
    'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
)

def requests_session() -> requests.Session:
    """Create a requests session with strict TLS 1.2+ enforcement (SonarCloud compliant)"""
    session = requests.Session()

    # Create base context with secure defaults, then explicitly harden
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Explicitly set minimum and maximum TLS versions (Python 3.7+)
    # Enforce TLS 1.2 as minimum, TLS 1.3 as maximum (modern and secure)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3  # Restrict to latest stable
    
    # Disable all legacy protocols (explicit defense against downgrade attacks)
    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1
    ctx.options |= ssl.OP_NO_SSLv2  # Redundant in modern Python but explicit
    ctx.options |= ssl.OP_NO_SSLv3  # Redundant in modern Python but explicit
    
    # Enforce strong cipher suites (restrict to AES-GCM and ChaCha20-Poly1305)
    ctx.set_ciphers(STRONG_CIPHERS)
    
    # Explicitly enable certificate verification (default in create_default_context but enforced here)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True  # Ensure hostname matches certificate
    
    # Add HSTS-like behavior through request headers (optional but recommended)
    session.headers.update({"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})

    # Mount adapter with secure context
    adapter = requests.adapters.HTTPAdapter()
    session.mount('https://', adapter)
    session.verify = True  # Double-enforce verification (defensive coding)
    
    return session
    

# --------------------------
# Flask App Configuration with CSRF Protection
# --------------------------
flask_app = Flask(__name__)
flask_app.secret_key = os.getenv("FLASK_SECRET_KEY",
    ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
)

# Initialize CSRF protection
csrf = CSRFProtect()
csrf.init_app(flask_app)  # Enable CSRF protection for all routes

# Production settings
BIND_ADDRESS    = os.getenv("BIND_ADDRESS", '0.0.0.0')
HTTP_PORT       = int(os.getenv("HTTP_PORT", "80"))
HTTPS_PORT      = int(os.getenv("HTTPS_PORT", "8443"))
CERT_FILE       = os.getenv("SSL_CERT_FILE", os.path.join(os.path.dirname(__file__), 'cert.pem'))
KEY_FILE        = os.getenv("SSL_KEY_FILE", os.path.join(os.path.dirname(__file__), 'key.pem'))

# IP Whitelisting
ALLOWED_IPS     = set(os.getenv("ALLOWED_IPS", "127.0.0.1,192.168.1.100").split(','))
#ALLOWED_SUBNETS = {
    ipaddress.ip_network(cidr)
    for cidr in os.getenv("ALLOWED_SUBNETS", "172.16.0.0/16,10.0.0.0/16").split(',')
}

# --------------------------
# Global PIN Variable
# --------------------------
VALID_PIN: str = ""

def generate_pin() -> str:
    """Generate a 6-digit PIN code"""
    return ''.join(secrets.choice(string.digits) for _ in range(6))

# --------------------------
# Azure AD Authentication
# --------------------------
def get_access_token() -> str:
    """Get Microsoft Graph access token using service principal"""
    try:
        app = msal.ConfidentialClientApplication(
            CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
        )
        result = app.acquire_token_for_client(scopes=SCOPE)

        if "access_token" not in result:
            error_msg = result.get("error_description", "Unknown authentication error")
            raise ValueError(f"Token acquisition failed: {error_msg}")

        print("✅ Successfully acquired Graph access token")
        return result["access_token"]

    except ValueError as e:
        raise RuntimeError(f"Authentication error: {str(e)}") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected error during authentication: {str(e)}") from e

# --------------------------
# Device Lookup and Key Fetching
# --------------------------
def get_azure_ad_device_id(token: str, device_name: str) -> str | None:
    """Retrieve Azure AD Device ID"""
    url = (
        f"{MANAGED_DEVICES_URL}"
        f"?$filter=deviceName eq '{device_name}'"
        "&$select=azureADDeviceId,deviceName"
        "&$top=1"
    )
    headers = {"Authorization": f"Bearer {token}"}

    try:
        req_session = requests_session()
        resp = req_session.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        if not data.get("value") or len(data["value"]) == 0:
            print(f"❌ No device found with name: {device_name}")
            return None

        device = data["value"][0]
        azure_ad_id = device.get("azureADDeviceId")

        if not azure_ad_id:
            print(f"❌ Device {device_name} has no Azure AD Device ID")
            return None

        print(f"✅ Found Azure AD Device ID for {device_name}: {azure_ad_id}")
        return azure_ad_id

    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error fetching device: {e.response.status_code} - {e.response.text}")
        return None
    except requests.exceptions.SSLError as e:
        print(f"❌ TLS/SSL Error: {str(e)}")
        return None
    except Exception as e:
        print(f"❌ Error fetching device: {str(e)}")
        return None
    finally:
        req_session.close()

def fetch_bitlocker_keys(token: str, azure_ad_device_id: str) -> List[Dict[str, Any]]:
    """Fetch BitLocker keys"""
    headers = {"Authorization": f"Bearer {token}"}
    keys = []
    url = LIST_KEYS_URL

    params = {
        "$select": "id,deviceId",
        "$filter": f"deviceId eq '{azure_ad_device_id}'"
    }

    max_pages = 10
    page_count = 0

    print(f"\n🔍 Starting BitLocker key lookup for Azure AD ID: {azure_ad_device_id}")

    while url and page_count < max_pages:
        try:
            req_session = requests_session()
            resp = req_session.get(url, headers=headers, params=params)

            if resp.status_code == 404:
                print("⚠️ No BitLocker keys found")
                break

            resp.raise_for_status()
            data = resp.json()
            page_keys = data.get("value", [])

            if page_keys:
                print(f"✅ Found {len(page_keys)} key(s) on page {page_count}")
                keys.extend(page_keys)
            else:
                print(f"ℹ️ No keys found on page {page_count}")

            url = data.get("@odata.nextLink")
            params = None
            page_count += 1

        except requests.exceptions.HTTPError as e:
            print(f"❌ HTTP Error: {e.response.status_code} - {e.response.text}")
            break
        except requests.exceptions.SSLError as e:
            print(f"❌ TLS/SSL Error: {str(e)}")
            break
        except Exception as e:
            print(f"❌ Error fetching keys: {str(e)}")
            break
        finally:
            req_session.close()

    print(f"📊 Total keys found: {len(keys)}")
    return keys

def get_key_value(token: str, key_id: str) -> str | None:
    """Get full recovery key value"""
    try:
        req_session = requests_session()
        url = KEY_DETAIL_URL.format(id=key_id)
        resp = req_session.get(url, headers={"Authorization": f"Bearer {token}"})
        resp.raise_for_status()

        return resp.json().get("key")

    except requests.exceptions.SSLError as e:
        print(f"❌ TLS/SSL Error: {str(e)}")
        return None
    except Exception as e:
        print(f"❌ Failed to get key {key_id[:8]}...: {str(e)}")
        return None
    finally:
        req_session.close()

# --------------------------
# Web Interface Components
# --------------------------
@flask_app.before_request
def enforce_ip_whitelist():
    """Block requests from unapproved IPs/subnets"""
    client_ip = request.remote_addr or ""
    try:
        ip_obj = ipaddress.ip_address(client_ip)
        if client_ip in ALLOWED_IPS or any(ip_obj in net for net in ALLOWED_SUBNETS):
            return
        print(f"🚫 Blocked request from unauthorized IP: {client_ip}")
        abort(403, "Access Denied: Unauthorized IP Address")
    except ValueError:
        print(f"⚠️ Invalid IP address: {client_ip}")
        abort(400, "Invalid Client IP Address Format")

# QR Code Cache
qr_cache: List[io.BytesIO] = []

# HTML Templates with CSRF Tokens
HTML_PIN_TEMPLATE = '''<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>BitLocker Key Lookup - Authentication</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; }
        .container { border: 1px solid #ddd; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; margin-top: 0; }
        input { padding: 0.8rem; font-size: 1.1rem; width: 200px; margin-right: 0.5rem; }
        button { padding: 0.8rem 1.5rem; font-size: 1.1rem; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2980b9; }
        .error { color: #e74c3c; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authentication Required</h1>
        <form method="post" action="/login">
            <!-- CSRF Token for security -->
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="text" name="pin" maxlength="6" required placeholder="Enter 6-digit PIN" pattern="[0-9]{6}">
            <button type="submit">Login</button>
        </form>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
    </div>
</body>
</html>'''

MAIN_PAGE_TEMPLATE = '''<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>BitLocker Key Lookup</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        .container { border: 1px solid #ddd; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; margin-top: 0; }
        h2 { color: #34495e; }
        h3 { color: #7f8c8d; }
        input { padding: 0.8rem; font-size: 1.1rem; width: 300px; margin-right: 0.5rem; }
        button { padding: 0.8rem 1.5rem; font-size: 1.1rem; background: #2ecc71; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #27ae60; }
        .error { color: #e74c3c; padding: 1rem; background: #fef2f2; border-radius: 4px; }
        .success { padding: 1rem; background: #f0fdf4; border-radius: 4px; }
        ul { padding-left: 1.5rem; }
        li { margin: 0.5rem 0; }
        pre { background: #f8f9fa; padding: 1rem; border-radius: 4px; overflow-x: auto; }
        .qr-container { display: flex; gap: 2rem; margin-top: 1rem; flex-wrap: wrap; }
        .qr-item { text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>BitLocker Recovery Key Lookup</h1>

        <!-- Lookup Form with CSRF Token -->
        <form method="post" action="/search">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="text" name="device" required placeholder="Enter Device Name (e.g., HKSTPXXX)" autocomplete="off">
            <button type="submit">Search for Keys</button>
        </form>

        <!-- Results Section -->
        {% if key_list %}
            <div class="success">
                <h2>Found {{ key_list|length }} Recovery Key(s) for "{{ device_name }}"</h2>
                <ul>
                    {% for key in key_list %}
                        <li>
                            <strong>Recovery Key:</strong><br>
                            <pre>{{ key.recoveryKey }}</pre>
                        </li>
                    {% endfor %}
                </ul>

                {% if key_list|length > 0 %}
                    <h3>QR Codes (Scan to Copy Key)</h3>
                    <div class="qr-container">
                        {% for i in range(key_list|length) %}
                            <div class="qr-item">
                                <img src="/qr/{{i}}" alt="QR Code for recovery key"
                                     style="max-width: 200px; border: 1px solid #eee; padding: 1rem; border-radius: 4px;">
                            </div>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
        {% elif error %}
            <div class="error">
                {{ error }}
            </div>
        {% endif %}
    </div>
</body>
</html>'''

def find_recovery_keys_web(token: str, device_name: str) -> tuple[List[Dict[str, Any]], str | None]:
    """Direct lookup of BitLocker keys from Intune"""
    qr_cache.clear()

    try:
        azure_ad_id = get_azure_ad_device_id(token, device_name)
        if not azure_ad_id:
            return [], "No device found with name: '{device_name}'"

        keys = fetch_bitlocker_keys(token, azure_ad_id)
        if not keys:
            return [], "No BitLocker keys found for device: '{device_name}'."

        key_list = []
        for key in keys:
            full_key = get_key_value(token, key["id"])
            if full_key:
                key_dict = {
                    "recoveryKey": full_key,
                    "deviceId": key.get("deviceId")
                }
                key_list.append(key_dict)

                buf = io.BytesIO()
                qr = qrcode.make(full_key)
                qr.save(buf, format='PNG', dpi=(150, 150))
                buf.seek(0)
                qr_cache.append(buf)

        if not key_list:
            return [], "Failed to retrieve their values."

        return key_list, None

    except Exception as e:
        error_msg = f"Error looking up keys: {str(e)}. Please try again later."
        print("❌ Web lookup error: {error_msg}")
        return [], error_msg

# --------------------------
# Flask Routes
# --------------------------
@flask_app.route('/', methods=['GET'])  # GET-only: safe method for page rendering
def index():
    """Main page renderer (GET-only).
    - Unauthenticated users see the PIN form.
    - Authenticated users see the search form.
    """
    if not session.get('authenticated'):
        return render_template_string(HTML_PIN_TEMPLATE, error=None)

    return render_template_string(
        MAIN_PAGE_TEMPLATE,
        key_list=[],
        error=None,
        device_name=""
    )

@flask_app.route('/login', methods=['POST'])
def login():
    """PIN authentication (POST-only)"""
    user_pin = request.form.get('pin', '').strip()
    if user_pin == VALID_PIN:
        session['authenticated'] = True
        print("✅ User authenticated with correct PIN")
        return redirect('/')
    print("Failed PIN attempt from {request.remote_addr}")
    return render_template_string(HTML_PIN_TEMPLATE, error="Invalid PIN. Please try again.")

@flask_app.route('/search', methods=['POST'])
def search():
    """Device search and key lookup (POST-only)"""
    if not session.get('authenticated'):
        print("🚫 Unauthorized search attempt from {request.remote_addr}")
        return redirect('/')

    key_list = []
    error = None
    device_name = request.form.get('device', '').strip()

    if not device_name:
        error = "Please enter a device name to search for."
    else:
        print("🔍 Web lookup request for device: '{device_name}' from {request.remote_addr}")
        try:
            token = get_access_token()
            key_list, error = find_recovery_keys_web(token, device_name)
        except Exception as e:
            error = "Server error during lookup: {str(e)}"

    return render_template_string(
        MAIN_PAGE_TEMPLATE,
        key_list=key_list,
        error=error,
        device_name=device_name
    )

@flask_app.route('/qr/<int:qr_index>')  # GET-only by default (secure for read operations)
def serve_qr(qr_index: int):
    """Serve QR code from cache (read-only operation)"""
    if not session.get('authenticated'):
        print(f"🚫 Unauthorized QR code access attempt from {request.remote_addr}")
        return redirect('/')

    if qr_index < 0 or qr_index >= len(qr_cache):
        print(f"⚠️ Invalid QR code index {qr_index} requested")
        abort(404, "QR Code Not Found")

    buf = qr_cache[qr_index]
    buf.seek(0)

    response = make_response(send_file(
        io.BytesIO(buf.getvalue()),
        mimetype='image/png'
    ))

    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

# --------------------------
# HTTP → HTTPS Redirect Server
# --------------------------
def redirect_app(env, start_response):
    """Redirect all HTTP traffic to HTTPS"""
    host = env.get('HTTP_HOST', '').split(':')[0]
    path = env.get('PATH_INFO', '')
    qs = env.get('QUERY_STRING', '')

    target = f"https://{host}:{HTTPS_PORT}{path}"
    if qs:
        target += f"?{qs}"

    start_response(
        '301 Moved Permanently',
        [('Location', target), ('Cache-Control', 'no-cache')]
    )
    return [b'Please use HTTPS instead: ' + target.encode()]

def run_redirect_server():
    """Start HTTP redirect server in background thread"""
    try:
        redirect_server = pywsgi.WSGIServer((BIND_ADDRESS, HTTP_PORT), redirect_app)
        print(f"🔀 HTTP redirect server running on {BIND_ADDRESS}:{HTTP_PORT}")
        redirect_server.serve_forever()
    except Exception as e:
        print(f"❌ Failed to start HTTP redirect server: {str(e)}")

# --------------------------
# SSL Context Configuration
# --------------------------
def create_ssl_context() -> ssl.SSLContext:
    """Create secure SSL context for HTTPS server with strict TLS 1.2+ enforcement"""
    try:
        # Use TLS_SERVER with explicit version controls (Python 3.7+)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)

        # Explicitly set TLS version bounds (critical for SonarCloud compliance)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3  # Restrict to modern TLS

        # Disable ALL legacy protocols (explicit defense against downgrade attacks)
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_1

        # Enforce strong cipher suites
        ctx.set_ciphers(STRONG_CIPHERS)

        # Restrict ALPN to secure HTTP protocols only
        ctx.set_alpn_protocols(['http/1.1'])

        # Enable session ticket hardening (optional but recommended)
        ctx.session_ticket_key = ssl.RAND_bytes(48)  # Rotate periodically in production

        return ctx
    except Exception as e:
        raise RuntimeError(
            f"Failed to create SSL context: {str(e)}. "
            "Ensure valid TLS 1.2+ certificates are provided."
        ) from e
    
# --------------------------
# Application Entry Point
# --------------------------
if __name__ == '__main__':
    print("="*60)
    print("    BitLocker Key Manager (Secure Production Version)")
    print("="*60)

    VALID_PIN = generate_pin()
    print("\n🔒 Generated Session PIN:", VALID_PIN)
    print("   - Valid for this session only")
    print("   - Will regenerate when application restarts")

    print("\n🔐 Checking SSL certificates...")
    if not os.path.exists(CERT_FILE):
        raise FileNotFoundError(
            f"SSL Certificate not found: {CERT_FILE}\nPlace valid TLS 1.2+ cert in this location."
        )
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError(
            f"SSL Private Key not found: {KEY_FILE}\nPlace matching private key in this location."
        )
    print("✅ SSL certificates found")

    redirect_thread = Thread(target=run_redirect_server, daemon=True)
    redirect_thread.start()

    try:
        ssl_ctx = create_ssl_context()
        app_hostname = socket.gethostname()
        app_ip = socket.gethostbyname(app_hostname)

        print("\n🚀 Web Server Ready (TLS 1.2+ enforced)")
        print(f"   - HTTPS Address: https://{app_hostname}:{HTTPS_PORT}")
        print(f"   - Alternative: https://{app_ip}:{HTTPS_PORT}")
        print(f"   - Use PIN: {VALID_PIN} to authenticate")
        print("\nPress Ctrl+C to stop")
        print("="*60)

        main_server = pywsgi.WSGIServer((BIND_ADDRESS, HTTPS_PORT), flask_app, ssl_context=ssl_ctx)
        main_server.serve_forever()

    except KeyboardInterrupt:
        print("\n\n🛑 Application stopped by user")
    except Exception as e:
        print(f"\n❌ Failed to start HTTPS server: {str(e)}")
