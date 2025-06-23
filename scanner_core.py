
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from requests.exceptions import RequestException

headers_to_check = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def safe_request(url, **kwargs):
    try:
        response = requests.get(url, timeout=10, **kwargs)
        return response
    except RequestException as e:
        return {"error": str(e)}

def check_url_status(url):
    response = safe_request(url)
    if isinstance(response, dict):
        return response
    return {"status_code": response.status_code, "reason": response.reason}

def check_security_headers(url):
    response = safe_request(url)
    if isinstance(response, dict):
        return response
    missing = [header for header in headers_to_check if header not in response.headers]
    return {"missing_headers": missing, "headers": dict(response.headers)}

def check_mixed_content(url):
    if not url.startswith("https://"):
        return {"error": "Site is not using HTTPS"}
    
    response = safe_request(url)
    if isinstance(response, dict):
        return response
    
    soup = BeautifulSoup(response.text, "html.parser")
    http_links = [tag['src'] for tag in soup.find_all(src=True) if tag['src'].startswith('http://')]
    http_links += [tag['href'] for tag in soup.find_all(href=True) if tag['href'].startswith('http://')]
    
    return {
        "insecure_links_found": len(http_links),
        "insecure_links": http_links
    }

def check_xss(url):
    payload = "<script>alert(1)</script>"
    try:
        response = requests.get(url, params={"input": payload}, timeout=10)
        if payload in response.text:
            return {"vulnerable": True, "test_url": response.url}
        return {"vulnerable": False}
    except Exception as e:
        return {"error": str(e)}

def check_sql_injection(url):
    payload = "' OR '1'='1"
    try:
        response = requests.get(url, params={"id": payload}, timeout=10)
        if any(keyword in response.text.lower() for keyword in ["sql", "syntax", "mysql", "database error", "warning"]):
            return {"vulnerable": True, "test_url": response.url}
        return {"vulnerable": False}
    except Exception as e:
        return {"error": str(e)}

def get_input_fields(url):
    response = safe_request(url)
    if isinstance(response, dict):
        return response
    
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    form_details = []

    for form in forms:
        inputs = form.find_all("input")
        form_data = {
            "action": form.get("action"),
            "method": form.get("method", "GET").upper(),
            "inputs": [i.get("name", "") for i in inputs if i.get("name")]
        }
        form_details.append(form_data)

    return {
        "forms_found": len(forms),
        "forms": form_details
    }

def check_cookie_flags(url):
    response = safe_request(url)
    if isinstance(response, dict):
        return response

    cookies = response.headers.get('set-cookie')
    if cookies:
        secure = "Secure" in cookies
        httponly = "HttpOnly" in cookies
        return {
            "Secure": secure,
            "HttpOnly": httponly
        }
    return {"message": "No cookies set"}

