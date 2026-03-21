import ssl
import socket
import datetime
import requests

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

RISKY_PORTS = {21, 23, 3306, 5432, 6379, 27017}

def check_ssl(hostname):
    results = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(8)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        # Expiry check
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.datetime.utcnow()).days
            if days_left < 0:
                sev, desc = "HIGH", f"SSL certificate EXPIRED {abs(days_left)} days ago."
            elif days_left < 30:
                sev, desc = "MEDIUM", f"SSL certificate expires in {days_left} days."
            else:
                sev, desc = "INFO", f"SSL certificate valid — expires in {days_left} days ({expire_date.date()})."
            results.append({
                "type": "SSL Certificate",
                "severity": sev,
                "location": f"{hostname}:443",
                "payload": expire_str,
                "description": desc,
                "recommendation": "Renew certificate before expiry." if days_left < 30 else "",
            })

        # Issuer info
        issuer = dict(x[0] for x in cert.get("issuer", []))
        results.append({
            "type": "SSL Issuer",
            "severity": "INFO",
            "location": f"{hostname}:443",
            "payload": issuer.get("organizationName", "Unknown"),
            "description": f"Certificate issued by: {issuer.get('organizationName', 'Unknown')}",
            "recommendation": "",
        })

    except ssl.SSLCertVerificationError:
        results.append({
            "type": "SSL Certificate",
            "severity": "HIGH",
            "location": f"{hostname}:443",
            "payload": "-",
            "description": "SSL certificate verification failed — self-signed or untrusted CA.",
            "recommendation": "Install a certificate from a trusted Certificate Authority.",
        })
    except ConnectionRefusedError:
        results.append({
            "type": "SSL Certificate",
            "severity": "MEDIUM",
            "location": f"{hostname}:443",
            "payload": "-",
            "description": "Port 443 not open — HTTPS may not be configured.",
            "recommendation": "Enable HTTPS on port 443.",
        })
    except Exception as e:
        results.append({
            "type": "SSL Check",
            "severity": "INFO",
            "location": hostname,
            "payload": "-",
            "description": f"SSL check could not complete: {str(e)}",
            "recommendation": "",
        })
    return results

def check_ports(hostname):
    results = []
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            sock.close()
            if result == 0:
                open_ports.append((port, service))
        except Exception:
            pass

    for port, service in open_ports:
        if port in RISKY_PORTS:
            results.append({
                "type": "Open Risky Port",
                "severity": "MEDIUM",
                "location": f"{hostname}:{port}",
                "payload": service,
                "description": f"Port {port} ({service}) is open — may expose sensitive service to internet.",
                "recommendation": f"Restrict access to port {port} using firewall rules if not needed publicly.",
            })
        else:
            results.append({
                "type": "Open Port",
                "severity": "INFO",
                "location": f"{hostname}:{port}",
                "payload": service,
                "description": f"Port {port} ({service}) is open.",
                "recommendation": "",
            })

    if not open_ports:
        results.append({
            "type": "Port Scan",
            "severity": "INFO",
            "location": hostname,
            "payload": "-",
            "description": "No common open ports detected (firewall may be blocking).",
            "recommendation": "",
        })

    return results

def scan(url):
    from urllib.parse import urlparse
    hostname = urlparse(url).hostname or url.replace("https://","").replace("http://","").split("/")[0]
    results = []
    results += check_ssl(hostname)
    results += check_ports(hostname)
    return results
