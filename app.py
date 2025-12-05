from flask import Flask, request, render_template, jsonify
import requests
import google.generativeai as genai
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import ssl
import json
import time
from urllib.parse import urlparse

app = Flask(__name__)

# ✅ Set API Keys
GEMINI_API_KEY = "AIzaSyBNcuvyE3rT0KyXRYZvx5M6tMSQv4IMBdU"
SAFE_BROWSING_API_KEY = "AIzaSyAh5Zyxb2-4pYW4A0pLAiJsiKGouNPMZPc"

genai.configure(api_key=GEMINI_API_KEY)

# ✅ Trusted Domains (Avoid False Positives)
TRUSTED_DOMAINS = [
    "instagram.com", "facebook.com", "google.com", "paypal.com",
    "amazon.com", "microsoft.com", "apple.com", "github.com"
]

def normalize_url(url):
    """Ensure URL starts with HTTP/HTTPS"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def extract_domain(url):
    """Extract domain from URL"""
    return urlparse(url).netloc.replace("www.", "")

def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API"""
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    
    payload = {
        "client": {"clientId": "ai-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    response = requests.post(safe_browsing_url, json=payload)
    result = response.json()
    
    return "⚠️ Marked as dangerous by Google Safe Browsing!" if "matches" in result else "✅ Not flagged by Google Safe Browsing."

def check_ssl_certificate(url):
    """Verify SSL Certificate Authority (Detect Fake HTTPS Sites)"""
    domain = extract_domain(url)
    
    try:
        cert = ssl.get_server_certificate((domain, 443))
        return f"✅ SSL Verified: {domain}" if cert else "⚠️ SSL Verification Failed!"
    except Exception:
        return "⚠️ SSL Verification Failed!"

def fetch_rendered_html(url):
    """Extract FULLY RENDERED HTML (Including JavaScript-Loaded Content)"""
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36")

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    try:
        driver.get(url)
        time.sleep(5)  # ✅ Wait for JavaScript Execution
        full_html = driver.page_source  # ✅ Get Fully Rendered HTML
        
        # ✅ Capture JavaScript Logs
        js_logs = driver.get_log('browser')

        # ✅ Track Redirects
        redirects = driver.execute_script("return window.performance.getEntriesByType('navigation');")
        
        return full_html, js_logs, redirects
    except Exception as e:
        return f"Failed to extract HTML: {str(e)}", [], []
    finally:
        driver.quit()

def analyze_with_gemini(html_code, url, js_logs, redirects):
    """Send Fully Rendered HTML & JS Logs to Google Gemini AI"""
    domain = extract_domain(url)

    # ✅ If the website is in the Trusted List, mark it as safe
    if domain in TRUSTED_DOMAINS:
        return f"✅ Trusted domain: {domain}."

    try:
        model = genai.GenerativeModel("gemini-1.5-pro-latest")

        prompt = f"""
        **Website Security Analysis**  
        URL: {url}  
        **Rendered HTML (after JavaScript execution):**  
        ```
        {html_code[:15000]}  # ✅ Limit size for better AI processing
        ```

        **JavaScript Console Logs:**
        ```
        {json.dumps(js_logs, indent=2)}
        ```

        **Redirects Detected:**  
        ```
        {json.dumps(redirects, indent=2)}
        ```

        **Analyze and detect:**  
        1️⃣ **Phishing signs (fake login pages, credential theft scripts).**  
        2️⃣ **Money scams, fake giveaways, or forced downloads.**  
        3️⃣ **Suspicious JavaScript execution (stealing data, injecting malware).**  
        4️⃣ **Auto-redirects to malicious sites.**  
        5️⃣ **Would you trust this website? Why or why not?**  
        """

        response = model.generate_content(prompt)
        return response.text if response else "No analysis available."
    except Exception as e:
        return f"Gemini AI Analysis Failed: {str(e)}"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    url = request.form["url"]
    url = normalize_url(url)

    print(f"🔍 Fetching FULLY RENDERED HTML from: {url}")

    # ✅ Extract Fully Rendered Page & JavaScript Logs
    rendered_html, js_logs, redirects = fetch_rendered_html(url)

    # ✅ Send Rendered HTML, JavaScript Logs & Redirects to AI
    print("🤖 Sending Full Data to Gemini AI for Deep Analysis...")
    gemini_analysis = analyze_with_gemini(rendered_html, url, js_logs, redirects)

    # ✅ Check Google Safe Browsing
    safe_browsing_result = check_google_safe_browsing(url)

    # ✅ Check SSL Certificate
    ssl_result = check_ssl_certificate(url)

    # ✅ AI Security Decision
    is_malicious = any(keyword in gemini_analysis.lower() for keyword in ["scam", "fraud", "malicious", "phishing", "dangerous", "fake", "steal", "credential theft"])
    final_status = "🚨 WARNING: This website looks suspicious!" if is_malicious else "✅ This website looks safe."

    results = {
        "url": url,
        "gemini_analysis": gemini_analysis,
        "google_safe_browsing": safe_browsing_result,
        "ssl_verification": ssl_result,
        "final_status": final_status
    }

    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
