import whois
import tldextract
from datetime import datetime

def get_domain_age(url):
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, datetime):
            return (datetime.utcnow() - creation_date).days
        else:
            return 0
    except:
        return 730.0  # fallback to neutral "safe" age

def get_whois_summary(url):
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        w = whois.whois(domain)

        registrar = w.registrar or "Unknown"
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, datetime):
            domain_age_days = (datetime.utcnow() - creation_date).days
            registration_date = creation_date.strftime("%Y-%m-%d")
        else:
            domain_age_days = 0
            registration_date = "Unknown"

        return {
            "registrar": registrar,
            "uses_https": url.startswith("https://"),
            "registration_date": registration_date,
            "domain_age_days": domain_age_days
        }

    except Exception:
        return {
            "registrar": "Unavailable",
            "uses_https": url.startswith("https://"),
            "registration_date": "Unavailable",
            "domain_age_days": 0
        }
