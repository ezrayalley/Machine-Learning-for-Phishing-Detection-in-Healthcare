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
def check_domain_registered(url):
    try:
        domain_info = whois.whois(url)
        return bool(domain_info.domain_name)
    except:
        return False

# Function to get web traffic rank
def get_web_traffic(url):
    # Placeholder: You can integrate an API for actual traffic data
    return 500000 if "google" in url else 0

# Function to check DNS record
def check_dns(url):
    try:
        requests.get(url, timeout=5)
        return True
    except:
        return False

# Function to count links in the webpage
def count_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        return len(soup.find_all("a"))
    except:
        return 0

# Function to check favicon presence
def check_favicon(url):
    try:
        response = requests.get(url)
        return 1 if "favicon" in response.text else 0
    except:
        return 0

# Function to get domain age
def get_domain_age(url):
    try:
        domain_info = whois.whois(url)
        if isinstance(domain_info.creation_date, list):
            return (pd.Timestamp.now() - pd.Timestamp(domain_info.creation_date[0])).days
        elif domain_info.creation_date:
            return (pd.Timestamp.now() - pd.Timestamp(domain_info.creation_date)).days
        return 0
    except:
        return 0

# Streamlit UI
st.set_page_config(page_title="Phishing Detector", page_icon="🚨", layout="centered")
st.markdown("<h1 style='text-align: center; color: red;'>🔍 Phishing Detection App</h1>", unsafe_allow_html=True)
st.sidebar.image("logo.png", use_column_width=True)
st.sidebar.info("This AI-powered tool helps detect phishing websites based on URL characteristics.")

# User input
url = st.text_input("🔗 Enter Website URL")

# Validate URL
valid_url = is_valid_url(url)

if st.button("🚀 Predict"):
    if valid_url:
        extracted_features = extract_features(url)
        
        if extracted_features is None:
            st.error("❌ Error extracting features. Please try another URL.")
        else:
            input_df = pd.DataFrame([extracted_features])
            input_df = input_df.reindex(columns=expected_features, fill_value=0)  # Ensure correct feature order
            
            # Show extracted features for debugging
            st.write("🔍 Extracted Features:", input_df)

            # Get phishing probability
            proba = model.predict_proba(input_df)[0]
            phishing_prob = proba[1]  # Probability of being phishing

            # Adjust threshold for better accuracy
            threshold = 0.8  # Increased from 0.5 to reduce false positives
            prediction = 1 if phishing_prob > threshold else 0

            if prediction == 1:
                st.error("⚠️ **Warning! This website is a Phishing Site!**")
            else:
                st.success("✅ **This website is Legitimate!**")
    else:
        st.warning("⚠️ Please enter a valid URL (must start with http:// or https://).")
