import os
import time
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from PIL import Image

# Path to ChromeDriver (Update this with your actual path)
CHROMEDRIVER_PATH = "C:\\Users\\shanm\\Downloads\\chromedriver-win64\\chromedriver-win64\\chromedriver.exe"

def is_valid_website(url):
    """Check if the URL is a valid website by sending a request."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True
    except requests.RequestException:
        return False
    return False

def take_screenshot(url, output_path="screenshot.png"):
    """Capture a screenshot of the given webpage."""
    options = Options()
    options.add_argument("--headless")  # Run Chrome in headless mode
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,720")

    service = Service(CHROMEDRIVER_PATH)
    driver = webdriver.Chrome(service=service, options=options)

    try:
        driver.get(url)
        time.sleep(3)  # Wait for the page to load
        driver.save_screenshot(output_path)
        print(f"Screenshot saved: {output_path}")
    except Exception as e:
        print(f"Error capturing screenshot: {e}")
    finally:
        driver.quit()

def check_link(link):
    """Determine if the link is a website and take a screenshot if valid."""
    if is_valid_website(link):
        print(f"✅ The link is a valid website: {link}")
        take_screenshot(link)
    else:
        print(f"❌ The link is NOT a valid website: {link}")

# Example usage
if __name__ == "__main__":
    user_link = input("Enter a URL to check: ")
    check_link(user_link)
