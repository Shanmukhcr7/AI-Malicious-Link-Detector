import whois
import requests
import re
import socket
from urllib.parse import urlparse

# Common suspicious words found in phishing URLs
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'bank', 'verify', 'free', 'update', 'account', 'paypal', 'confirm']

# Known URL shorteners
SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'shorte.st', 'adf.ly', 'ow.ly', 'is.gd']

def check_https(url):
    """Check if the URL uses HTTPS"""
    return url.startswith("https://")

def check_ssl(url):
    """Check if the site has a valid SSL certificate"""
    domain = urlparse(url).netloc
    try:
        socket.getaddrinfo(domain, 443)  # Check if port 443 (SSL) is open
        return True
    except:
        return False

def check_whois(url):
    """Get domain information using WHOIS lookup"""
    try:
        domain = urlparse(url).netloc
        whois_info = whois.whois(domain)
        if whois_info.creation_date:
            return whois_info
    except:
        return None

def check_redirects(url):
    """Check for excessive redirects"""
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return len(response.history) <= 3  # More than 3 redirects could indicate phishing
    except:
        return False

def check_suspicious_keywords(url):
    """Check if the URL contains suspicious words"""
    return any(word in url.lower() for word in SUSPICIOUS_KEYWORDS)

def check_shortened_url(url):
    """Check if the URL is from a known URL shortener"""
    domain = urlparse(url).netloc
    return any(short in domain for short in SHORTENERS)

def check_domain_age(whois_info):
    """Check if the domain is recently created (less than 6 months old)"""
    from datetime import datetime
    if whois_info and whois_info.creation_date:
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):  # Some WHOIS results return a list
            creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days
        return age_days >= 180  # 6 months
    return False

def check_subdomains(url):
    """Check if the domain has too many subdomains (common in phishing URLs)"""
    domain = urlparse(url).netloc
    subdomains = domain.split('.')
    return len(subdomains) <= 3  # Example: "secure.bank.com" is fine, but "login.bank.secure.com" is suspicious

def check_url_safety(url):
    """Run all security checks"""
    print(f"\n🔍 Checking URL: {url}")

    # HTTPS check
    if check_https(url):
        print("✅ Uses HTTPS (secure connection).")
    else:
        print("❌ Uses HTTP (not secure).")

    # SSL certificate check
    if check_ssl(url):
        print("✅ The website has an SSL certificate (padlock icon).")
    else:
        print("❌ No SSL certificate detected.")

    # WHOIS Lookup
    whois_info = check_whois(url)
    if whois_info:
        print("✅ WHOIS lookup successful.")
        if not check_domain_age(whois_info):
            print("⚠️ The domain is **new** (less than 6 months old), which could be risky.")
    else:
        print("⚠️ WHOIS lookup failed or domain information is hidden.")

    # Redirect check
    if check_redirects(url):
        print("✅ The URL does not redirect excessively.")
    else:
        print("⚠️ The URL has excessive redirects, which may be a phishing sign.")

    # Suspicious keywords check
    if check_suspicious_keywords(url):
        print("⚠️ The URL contains **suspicious words** (e.g., login, secure, bank).")
    
    # Shortened URL check
    if check_shortened_url(url):
        print("⚠️ The URL is **shortened** (e.g., bit.ly, tinyurl). This can hide its true destination.")

    # Subdomain check
    if not check_subdomains(url):
        print("⚠️ The domain has **too many subdomains**, which may be suspicious.")

    print("\n🔹 **Final Verdict:**")
    if not check_https(url) or not check_ssl(url) or check_suspicious_keywords(url) or check_shortened_url(url):
        print("⚠️ **The URL looks suspicious! Proceed with caution.**")
    else:
        print("✅ **The URL looks safe.**")

# Get user input and run checks
if __name__ == "__main__":
    user_url = input("Enter a URL to check: ")
    check_url_safety(user_url)
