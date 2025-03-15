import streamlit as st
import pandas as pd
import joblib
import tldextract
import requests
from bs4 import BeautifulSoup
import whois

# Load trained model
model = joblib.load("phishing_model.pkl")  # Ensure correct path

# Expected features from training
expected_features = [
    'length_of_url', 'having_at_symbol', 'double-slash_redirection', 'prefix and suffix',
    'sub_domains', 'domain_registered', 'favicons', 'ports', 'https', 'external_objects',
    'anchor_tags', 'links_in_tags', 'sfh-domain', 'abnoramal_url', 'on_mouse_over',
    'right_click', 'popup_windows', 'domain_age', 'dns_record', 'web_traffic',
    'links_pointing', 'statistical_report', 'image_text_keyword'
]

# Function to validate URL
def is_valid_url(url):
    return url.startswith(("http://", "https://"))

# Function to extract features
def extract_features(url):
    try:
        ext = tldextract.extract(url)
        features = {
            "length_of_url": len(url),
            "having_at_symbol": 1 if "@" in url else 0,
            "double-slash_redirection": 1 if "//" in url[7:] else 0,
            "prefix and suffix": 1 if "-" in ext.domain else 0,
            "sub_domains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
            "domain_registered": 1 if check_domain_registered(url) else 0,
            "https": 1 if url.startswith("https://") else 0,
            "web_traffic": get_web_traffic(url),
            "dns_record": 1 if check_dns(url) else 0,
            "links_pointing": count_links(url),
            "statistical_report": 0,  # Placeholder
            "favicons": check_favicon(url),
            "ports": 0,  # Default
            "external_objects": 0,  # Default
            "anchor_tags": 0,  # Default
            "links_in_tags": 0,  # Default
            "sfh-domain": 0,  # Default
            "abnoramal_url": 0,  # Default
            "on_mouse_over": 0,  # Default
            "right_click": 0,  # Default
            "popup_windows": 0,  # Default
            "domain_age": get_domain_age(url),
            "image_text_keyword": 0  # Default
        }
        return features
    except Exception as e:
        st.error(f"Feature extraction error: {e}")
        return None

# Function to check domain registration

# The remaining codes are hidden
# To get full acces contact: ezra.yalley@gmail.com
