from datetime import datetime
from flask import Flask, render_template, request
import pandas as pd
from urllib.parse import urlparse
import joblib
import ipaddress
import re

app = Flask(__name__)

# Load trained model
model = joblib.load("phishing_url_model.pkl")

# Load feature order
feature_columns = joblib.load("feature_columns.pkl")


# -----------------------------
# URL Feature Extraction
# -----------------------------


    # IMPORTANT:
    # Paste your complete 18-feature
    # extract_url_features() logic here.
def extract_basic_url_features(url):
        # Add scheme if user doesn't provide one
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        domain = parsed.netloc.split('@')[-1].split(':')[0]

        # Remove www. for subdomain calculations
        domain_without_www = domain.lower()
        if domain_without_www.startswith('www.'):
            domain_without_www = domain_without_www[4:]

        # Check if domain is an IP address
        try:
            ipaddress.ip_address(domain_without_www)
            is_domain_ip = 1
        except ValueError:
            is_domain_ip = 0

        # Extract TLD
        if is_domain_ip == 1:
            tld = ''
            no_of_subdomain = 0

        else:
            domain_parts = domain_without_www.split('.')

            tld = domain_parts[-1] if len(domain_parts) > 1 else ''

            no_of_subdomain = max(len(domain_parts) - 2, 0)
            
        

        # URL statistics
        url_length = len(url)
        domain_length = len(domain)

        no_of_letters = sum(c.isalpha() for c in url)
        no_of_digits = sum(c.isdigit() for c in url)

        special_chars = set('!@#$%^&*()_+=[]{}|;:,<>?/~`-.')

        no_of_other_special_chars = sum(
            c in special_chars for c in url
        )

        no_of_equals = url.count('=')
        no_of_qmark = url.count('?')
        no_of_ampersand = url.count('&')

        # HTTPS
        is_https = 1 if parsed.scheme == 'https' else 0

        #TLD length
        tld_length = len(tld)

        # -----------------------------------
        # 14. Ratios
        # -----------------------------------
        letter_ratio = (
            no_of_letters / url_length
            if url_length > 0 else 0
        )
        
        digit_ratio = (
            no_of_digits / url_length
            if url_length > 0 else 0
        )

        special_char_ratio = (
            no_of_other_special_chars / url_length
            if url_length > 0 else 0
        )

        # -----------------------------------
        # 15. Obfuscation
        # -----------------------------------
        obfuscated_matches = re.findall(
            r'%[0-9a-fA-F]{2}',
            url
        )

        no_of_obfuscated_char = len(obfuscated_matches)

        has_obfuscation = (
            1 if no_of_obfuscated_char > 0 else 0
        )

        obfuscation_ratio = (
            no_of_obfuscated_char / url_length
            if url_length > 0 else 0
        )

        # -----------------------------------
        # 16. Return all features
        # -----------------------------------
        return {
            'URLLength': url_length,
            'DomainLength': domain_length,
            'IsDomainIP': is_domain_ip,
            'NoOfSubDomain': no_of_subdomain,
            'HasObfuscation': has_obfuscation,
            'NoOfObfuscatedChar': no_of_obfuscated_char,
            'ObfuscationRatio': obfuscation_ratio,
            'NoOfLettersInURL': no_of_letters,
            'LetterRatioInURL': letter_ratio,
            'NoOfDegitsInURL': no_of_digits,
            'DegitRatioInURL': digit_ratio,
            'NoOfEqualsInURL': no_of_equals,
            'NoOfQMarkInURL': no_of_qmark,
            'NoOfAmpersandInURL': no_of_ampersand,
            'NoOfOtherSpecialCharsInURL': no_of_other_special_chars,
            'SpacialCharRatioInURL': special_char_ratio,
            'IsHTTPS': is_https,
            'TLDLength': tld_length
        }   


history = []

# -----------------------------
# Home Page
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    probability = None
    url = ""

    if request.method == "POST":

        try:
            url = request.form["url"]

            print("URL received:", url)

            # Extract features
            features = extract_basic_url_features(url)
            print("Features:", features)

            # Convert to DataFrame
            input_df = pd.DataFrame([features])
            print("Input shape:", input_df.shape)

            # Ensure correct feature order
            input_df = input_df[feature_columns]
            print("Feature columns matched successfully")

            # Prediction
            prediction = model.predict(input_df)[0]
            print("Prediction:", prediction)

            # Probability
            probabilities = model.predict_proba(input_df)[0]
            print("Probabilities:", probabilities)

            if prediction == 0:
                result = "Phishing URL"
                probability = round(probabilities[0] * 100, 2)
            else:
                result = "Legitimate URL"
                probability = round(probabilities[1] * 100, 2)

            # Add scan to history
            history.append({
                "time": datetime.now().strftime("%d-%m-%Y %I:%M:%S %p"),
                "url": url,
                "result": result,
                "probability": f"{probability}%",
            })    

        except Exception as e:

            print("ERROR:", repr(e))

            return f"""
            <h1>Prediction Error</h1>
            <p><b>Error:</b> {repr(e)}</p>
            """, 500

    return render_template(
        "index.html",
        result=result,
        probability=probability,
        url=url,
        history=history
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
