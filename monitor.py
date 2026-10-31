import os
import sys
import json
import logging
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import requests

try:
    import psycopg2
except ImportError:
    psycopg2 = None

try:
    from pymongo import MongoClient
except ImportError:
    MongoClient = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

HISTORY_FILE = "incident_history.json"

def log_incident(target_name, target_type, status, message):
    """Logs check events to a local JSON history file."""
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            history = []

    incident_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "name": target_name,
        "type": target_type,
        "status": status,
        "details": message
    }
    
    history.insert(0, incident_entry)
    history = history[:100]

    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to write incident history: {e}")

def check_ssl_expiration(url, warning_days=15):
    """Checks the SSL certificate expiration date for HTTPS endpoints."""
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https":
        return None, None

    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                if not_after:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_date - datetime.utcnow()).days
                    return days_remaining, expiry_date.strftime('%Y-%m-%d')
    except Exception as e:
        logging.error(f"SSL check failed for {hostname}: {e}")
        return -1, str(e)
    
    return None, None

def check_postgres(conn_string, timeout=5):
    """Tests PostgreSQL database connection and measures latency."""
    if not psycopg2:
        return False, 0, "psycopg2 library missing"

    start_time = datetime.utcnow()
    try:
        conn = psycopg2.connect(conn_string, connect_timeout=timeout)
        conn.close()
        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        return True, latency, "Connection successful"
    except Exception as e:
        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        return False, latency, str(e)

def check_mongodb(conn_string, timeout=5):
    """Tests MongoDB connection using server ping and measures latency."""
    if not MongoClient:
        return False, 0, "pymongo library missing"

    start_time = datetime.utcnow()
    try:
        client = MongoClient(conn_string, serverSelectionTimeoutMS=timeout*1000)
        client.admin.command('ping')
        client.close()
        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        return True, latency, "Connection successful"
    except Exception as e:
        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        return False, latency, str(e)

def send_alert(webhook_url, message, is_discord=False):
    """Dispatches formatted alert payloads to Slack or Discord webhooks."""
    if not webhook_url:
        logging.warning("Webhook URL not configured. Skipping alert dispatch.")
        return

    payload = {"content" if is_discord else "text": message}
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code >= 400:
            logging.error(f"Failed to send webhook alert. Status: {response.status_code}")
    except Exception as e:
        logging.error(f"Exception occurred while sending webhook alert: {e}")

def monitor_endpoints():
    if not os.path.exists("endpoints.json"):
        logging.error("endpoints.json configuration file not found!")
        sys.exit(1)

    with open("endpoints.json", "r") as f:
        endpoints = json.load(f)

    slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
    discord_webhook = os.getenv("DISCORD_WEBHOOK_URL")
    webhook_url = discord_webhook or slack_webhook
    is_discord = bool(discord_webhook)

    failures = 0

    for endpoint in endpoints:
        name = endpoint.get("name", "Unnamed Target")
        target_type = endpoint.get("type", "http").lower()
        timeout = endpoint.get("timeout", 5)

        logging.info(f"Checking [{target_type.upper()}] {name}...")

        if target_type == "http":
            url = endpoint.get("url")
            method = endpoint.get("method", "GET")

            ssl_days, ssl_expiry = check_ssl_expiration(url)
            if ssl_days is not None and ssl_days < 15 and ssl_days >= 0:
                ssl_msg = f"⚠️ **SSL Warning**: Certificate for `{name}` expires in **{ssl_days} days** ({ssl_expiry})."
                logging.warning(ssl_msg)
                send_alert(webhook_url, ssl_msg, is_discord)
                log_incident(name, "http", "WARNING", ssl_msg)

            start_time = datetime.utcnow()
            try:
                response = requests.request(method, url, timeout=timeout)
                latency = (datetime.utcnow() - start_time).total_seconds() * 1000

                if response.status_code >= 400:
                    err_msg = f"🚨 **Uptime Alert**: `{name}` returned status code **{response.status_code}**! (Latency: {latency:.2f}ms)"
                    logging.error(err_msg)
                    send_alert(webhook_url, err_msg, is_discord)
                    log_incident(name, "http", "DOWN", err_msg)
                    failures += 1
                else:
                    success_msg = f"✅ {name} is UP. Status: {response.status_code} | Latency: {latency:.2f}ms"
                    logging.info(success_msg)
                    log_incident(name, "http", "UP", success_msg)

            except requests.exceptions.RequestException as e:
                err_msg = f"🔥 **Endpoint Down**: Failed to reach `{name}` ({url}). Error: `{str(e)}`"
                logging.error(err_msg)
                send_alert(webhook_url, err_msg, is_discord)
                log_incident(name, "http", "DOWN", err_msg)
                failures += 1

        elif target_type in ["postgres", "postgresql"]:
            conn_string = endpoint.get("connection_string")
            is_up, latency, details = check_postgres(conn_string, timeout)

            if not is_up:
                err_msg = f"🚨 **DB Down Alert**: PostgreSQL instance `{name}` failed connection check. Error: `{details}` (Latency: {latency:.2f}ms)"
                logging.error(err_msg)
                send_alert(webhook_url, err_msg, is_discord)
                log_incident(name, "postgres", "DOWN", err_msg)
                failures += 1
            else:
                success_msg = f"✅ PostgreSQL `{name}` is UP. Latency: {latency:.2f}ms"
                logging.info(success_msg)
                log_incident(name, "postgres", "UP", success_msg)

        elif target_type == "mongodb":
            conn_string = endpoint.get("connection_string")
            is_up, latency, details = check_mongodb(conn_string, timeout)

            if not is_up:
                err_msg = f"🚨 **DB Down Alert**: MongoDB cluster `{name}` failed ping check. Error: `{details}` (Latency: {latency:.2f}ms)"
                logging.error(err_msg)
                send_alert(webhook_url, err_msg, is_discord)
                log_incident(name, "mongodb", "DOWN", err_msg)
                failures += 1
            else:
                success_msg = f"✅ MongoDB `{name}` is UP. Latency: {latency:.2f}ms"
                logging.info(success_msg)
                log_incident(name, "mongodb", "UP", success_msg)

    if failures > 0:
        sys.exit(1)
import http.server
import socketserver

def serve_dashboard(port=8000):
    """Launches a local static web server to render index.html."""
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), Handler) as httpd:
        logging.info(f"Dashboard available locally at http://localhost:{port}")
        httpd.serve_forever()

if __name__ == "__main__":
    monitor_endpoints()
    
    # Optional local flag: run `python monitor.py --serve` to view the dashboard
if "--serve" in sys.argv:
        serve_dashboard()
