import secrets
import string
import random
import subprocess
import re
import os
import re
import pandas as pd
import bcrypt
import africastalking
import streamlit as st 
import google.generativeai as genai


from captcha.image import ImageCaptcha
from PIL import Image 
from urllib.parse import urlparse


from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key = os.getenv("GOOGLE_API_KEY"))

africastalking.initialize(
    username='EMID',
    api_key = os.getenv("AT_API_KEY")
)

sms = africastalking.SMS
airtime = africastalking.Airtime
voice = africastalking.Voice

def send_sms(phone_number, otp_sms):
    # amount = "10"
    # currency_code = "KES"

    recipients = [f"+254{str(phone_number)}"]

    # airtime_rec = "+254" + str(phone_number)

    print(recipients)
    print(phone_number)

    # Set your message
    message = f"{otp_sms}";

    # Set your shortCode or senderId
    sender = 20880

    try:
        # responses = airtime.send(phone_number=airtime_rec, amount=amount, currency_code=currency_code)
        response = sms.send(message, recipients, sender)

        print(response)

        # print(responses)

    except Exception as e:
        print(f'Houston, we have a problem: {e}')

    st.toast(f"OTP Sent Successfully")



def make_call(phone_number):    
  
  # Set your Africa's Talking phone number in international format
    callFrom = "+254730731123"
  
  # Set the numbers you want to call to in a comma-separated list
    callTo   = [f"+254{str(phone_number)}"]
    
    try:
  # Make the call
        result = voice.call(callFrom, callTo)
        print (result)
    except Exception as e:
        print ("Encountered an error while making the call:%s" %str(e))



def generate_otp(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

# print("Generated OTP:", generate_otp())





def check_email(email):
    try:
        result = subprocess.run(
            ['holehe', email],
            capture_output=True,
            text=True,
            check=True  
        )
        # df = pd.DataFrame(result)
        # st.dataframe(df.head(10))
        return st.write(result.stdout) 
    except subprocess.CalledProcessError as e:
        return st.error(f"Error: {e.stderr}")
    except FileNotFoundError:
        return st.error(f"Error: 'holehe' tool not found. Is it installed and in PATH?")





def generate_captcha_text(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_captcha_image(captcha_text, image_width=300):
    image = ImageCaptcha(image_width)
    image_file = f"{captcha_text}.png"
    image.write(captcha_text, image_file)
    return st.image(image_file)


# captcha_text = generate_captcha_text()
# image_file = generate_captcha_image(captcha_text)

# print("Generated Captcha")
# Image.open(image_file)




# Sample phishing keywords (you can expand this list or load from a file/database)
PHISHING_KEYWORDS = [
    "verify your account", "urgent", "click here", "reset password",
    "login immediately", "confirm your identity", "act now", "suspend",
    "unusual activity", "security alert", "free gift", "bank account"
]

SUSPICIOUS_LINK_PATTERN = r'https?://[^\s]+'  # Regex for detecting URLs

def phishing_score(email_content):
    score = 0
    email_content = email_content.lower()

    # Keyword scoring
    for keyword in PHISHING_KEYWORDS:
        if keyword in email_content:
            score += 10

    # Link detection scoring
    links = re.findall(SUSPICIOUS_LINK_PATTERN, email_content)
    score += len(links) * 5

    # Check for email requesting credentials
    if "password" in email_content and "email" in email_content:
        score += 15

    # Final scoring logic
    if score >= 30:
        verdict = "⚠️ High Phishing Risk"
    elif 15 <= score < 30:
        verdict = "🟠 Suspicious - Review Needed"
    else:
        verdict = "✅ Safe"

    return {
        "score": score,
        "verdict": verdict,
        "links_found": links
    }

# Example email scan
email_example = """

All the Visuals You Need—for Less!
 
 ‌ 
This week only, get 20% off everything at iStock. And when we say everything, we mean everything. Use code SAVE20 at checkout to save on plans and high‑quality visuals from a creative library free of AI‑generated content.
Essential photos, videos, and illustrations
Exclusive visuals from our Signature Collection
All annual and monthly subscriptions
Our Unlimited AI plan to access iStock's AI Generator and AI‑editing tools
 ‌ 
 ‌ 
Don't miss your chance to save!

 
"""

# result = phishing_score(email_example)
# print("Phishing Score:", result['score'])
# print("Verdict:", result['verdict'])
# print("Links Detected:", result['links_found'])






# Suspicious keywords often used by phishers
SUSPICIOUS_KEYWORDS = ['support', 'admin', 'security', 'account', 'service', 'verify', 'update', 'confirm']

# Common temporary / disposable domains list (extend as needed)
TEMP_EMAIL_DOMAINS = [
    'mailinator.com', 'guerrillamail.com', '10minutemail.com', 
    'tempmail.com', 'trashmail.com', 'yopmail.com'
]

# Function to detect phishing likelihood in email address
def analyze_email_address(email):
    score = 0
    email = email.lower()
    
    # Basic validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"score": 100, "verdict": "🚨 Invalid Email Format - Likely Fake"}

    local_part, domain = email.split('@')
    
    # Check for suspicious keywords in the local part
    for word in SUSPICIOUS_KEYWORDS:
        if word in local_part:
            score += 15
    
    # Check if domain is a known temporary/disposable email service
    if domain in TEMP_EMAIL_DOMAINS:
        score += 50

    # Check for typosquatting pattern (double letters, common mistakes)
    typo_patterns = ['gmaiil', 'outlok', 'yaho0', 'paypa1', 'faceboook']
    for typo in typo_patterns:
        if typo in domain:
            score += 30

    # Verdict based on score
    if score >= 50:
        verdict = st.write(f"🚨 High Risk of PHISHING")
    elif 20 <= score < 50:
        verdict = st.write(f"⚠️ Suspicious - Check Carefully")
    else:
        verdict = st.write(f"✅ Looks Legit")

    return {
        "score": score,
        "verdict": verdict,
        "local_part": local_part,
        "domain": domain
    }

# Example Usage
emails = [
    "antonriziki@gmail.com",
    "supportcenter@paypal.com",
    "random_user@guerrillamail.com",
    "security-update@secure-outlook.com",
    "info@echominds.africa"
]

# for email in emails:
#     result = analyze_email_address(email)
#     print(f"\nEmail: {email}")
#     print(f"Score: {result['score']}")
#     print(f"Verdict: {result['verdict']}")





# Suspicious patterns to check in URLs
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'account', 'bank', 'update', 'verify', 'confirm', 'webscr', 'wp-content']
SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rb.gy']
PHISHING_EXTENSIONS = ['.exe', '.scr', '.zip', '.rar']

def analyze_url(url):
    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Check if URL is using known shortening service
    if any(shortener in domain for shortener in SHORTENERS):
        score += 40

    # Check for suspicious keywords in URL path or domain
    for word in SUSPICIOUS_KEYWORDS:
        if word in domain or word in path:
            score += 20

    # Check if URL ends with dangerous file extensions
    if any(path.endswith(ext) for ext in PHISHING_EXTENSIONS):
        score += 50

    # Check for multiple '-' or '@' (common in phishing URLs)
    if '-' in domain or '@' in url:
        score += 15

    # Check for IP address instead of domain
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 40

    # Final verdict
    if score >= 60:
        verdict = st.write(f"🚨 HIGH RISK - Likely PHISHING")
    elif 30 <= score < 60:
        verdict = st.write(f"⚠️ Suspicious - Check Carefully")
    else:
        verdict = st.write(f"✅ Looks Safe")

    return {
        'url': url,
        'score': score,
        'verdict': verdict,
        'domain': domain
    }

# Example URLs to test
urls = [
    "https://secure-login-paypal.com/login",
    "https://bit.ly/3xU56fd",
    "http://192.168.0.1/account/verify",
    "https://safaricom.co.ke/myaccount",
    "https://malicious-site.com/file.zip"
]

# for u in urls:
#     result = analyze_url(u)
#     print(f"\nURL: {result['url']}")
#     print(f"Domain: {result['domain']}")
#     print(f"Score: {result['score']}")
#     print(f"Verdict: {result['verdict']}")





def check_and_encrypt_password(password: str, confirm_password: str):
    """ 
    Checks password match, validates strength, and encrypts password.
    
    Returns:
        - Encrypted password (if valid)
        - Error message (if invalid)
    """

    # Check if passwords match
    if password != confirm_password:
        return st.error("Error: Passwords do not match!")

    # Check password strength (at least 8 chars, 1 uppercase, 1 digit, 1 special char)
    if len(password) < 8:
        return st.error(f"Error: Password must be at least 8 characters long!")
    
    if not re.search(r"[A-Z]", password):
        return st.error(f"Error: Password must contain at least one uppercase letter!")
    
    if not re.search(r"\d", password):
        return st.error(f"Error: Password must contain at least one number!")
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return st.error(f"Error: Password must contain at least one special character!")

    # Encrypt password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    return st.text_input(label='Encrypted password', value=hashed_password.decode(), type='password')

# # Example usage
# password = "StrongP@ss123"
# confirm_password = "StrongP@ss123"

# result = check_and_encrypt_password(password, confirm_password)
# print(result)
