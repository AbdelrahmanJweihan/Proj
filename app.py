from flask import Flask, request as fRequest, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
import openai
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
import urllib.request
import urllib.parse
import time
import configparser
from functools import wraps

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')

app = Flask(__name__)
app.config['MYSQL_HOST'] = config.get('DATABASE', 'HOST')
app.config['MYSQL_USER'] = config.get('DATABASE', 'USER')
app.config['MYSQL_PASSWORD'] = config.get('DATABASE', 'PASSWORD')
app.config['MYSQL_DB'] = config.get('DATABASE', 'DB_NAME')

mysql = MySQL(app)
CORS(app, resources={r"/api/*": {"origins": config.get('CORS', 'ALLOWED_ORIGINS')}})

# Constants
VT_API_KEY = config.get('API_KEYS', 'VIRUSTOTAL_API_KEY')
SAFEBROWSING_API_KEY = config.get('API_KEYS', 'GOOGLE_SAFEBROWSING_API_KEY')
OPENAI_API_KEY = config.get('API_KEYS', 'OPENAI_API_KEY')
OPENAI_MODEL = "text-davinci-003"

# Rate limiting decorator
def rate_limit(max_per_minute):
    def decorator(f):
        calls = []

        @wraps(f)
        def wrapper(*args, **kwargs):
            now = time.time()
            calls_in_time = [call for call in calls if call > now - 60]

            if len(calls_in_time) >= max_per_minute:
                return jsonify({"error": "Rate limit exceeded"}), 429

            calls.append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def extract_urls_from_email(anchor):
    """Extract URLs from email anchors"""
    return [key['url'] for key in anchor if 'url' in key]

def extract_files_from_email(attachment):
    """Extract file URLs from email attachments"""
    return [key['href'] for key in attachment if 'href' in key]

def scan_url_with_virustotal(url, vt):
    """Scan a single URL with VirusTotal"""
    try:
        resp_url = vt.get_url_report(url)
        return json.loads(json.dumps(resp_url, sort_keys=False, indent=4))
    except Exception as e:
        print(f"VirusTotal scan failed for {url}: {str(e)}")
        return None

def scan_urls_for_malicious_content(urls_list):
    """Check URLs against multiple threat databases"""
    threats = []
    vt = VirusTotalPublicApi(VT_API_KEY)

    for url in urls_list:
        # VirusTotal check
        vt_result = scan_url_with_virustotal(url, vt)
        if vt_result and vt_result.get('positives', 0) > 0:
            threats.append(f"VirusTotal detected {vt_result['positives']} threats in {url}")
            continue

        # Google Safe Browsing check
        try:
            safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFEBROWSING_API_KEY}"
            threat_info = {
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            request_data = json.dumps(threat_info).encode()
            req = urllib.request.Request(safe_browsing_url, data=request_data,
                                      headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode())
                if response_data.get("matches"):
                    for match in response_data["matches"]:
                        threats.append(f"{match['threatType']} threat found in {url}")
        except Exception as e:
            print(f"Safe Browsing check failed for {url}: {str(e)}")

    return threats

def scan_files_for_malicious_content(files_list):
    """Check files against VirusTotal"""
    max_positives = 0
    vt = VirusTotalPublicApi(VT_API_KEY)

    for file_url in files_list:
        try:
            resp_file = vt.get_url_report(file_url)
            result = json.loads(json.dumps(resp_file, sort_keys=False, indent=4))
            if result.get('positives', 0) > max_positives:
                max_positives = result['positives']
        except Exception as e:
            print(f"File scan failed for {file_url}: {str(e)}")

    return max_positives

def generate_analysis_prompt(sender, title, mainBody):
    """Generate prompt for AI analysis"""
    return f"""
    Analyze this email for phishing indicators:
    Sender: {sender}
    Subject: {title}
    Body: {mainBody}

    Consider these aspects:
    1. Urgency or threats in language
    2. Suspicious sender address
    3. Requests for sensitive information
    4. Grammar/spelling errors
    5. Mismatched URLs
    6. Unusual requests

    Provide:
    - Phishing likelihood (High/Medium/Low)
    - Key indicators found
    - Recommended action
    - Detailed explanation
    """

def analyze_with_openai(prompt):
    """Get analysis from OpenAI"""
    try:
        response = openai.Completion.create(
            engine=OPENAI_MODEL,
            prompt=prompt,
            max_tokens=512,
            temperature=0.7,
            top_p=1,
            frequency_penalty=0,
            presence_penalty=0
        )
        return response.choices[0].text.strip()
    except Exception as e:
        print(f"OpenAI analysis failed: {str(e)}")
        return "Could not analyze email content due to service error"

def analyze_sentiment(text):
    """Get sentiment analysis from OpenAI"""
    try:
        response = openai.Completion.create(
            engine=OPENAI_MODEL,
            prompt=f"Classify this text's sentiment in one word (Positive/Neutral/Negative): {text}",
            max_tokens=10,
            temperature=0.3
        )
        return response.choices[0].text.strip()
    except Exception as e:
        print(f"Sentiment analysis failed: {str(e)}")
        return "Neutral"

@app.route('/api/analyze', methods=['POST'])
@rate_limit(max_per_minute=30)  # Limit to 30 requests per minute
@cross_origin()
def analyse():
    start_time = time.perf_counter()

    try:
        body = fRequest.get_json()
        if not body:
            return jsonify({"error": "No data provided"}), 400

        # Input validation
        required_fields = ['title', 'sender', 'body', 'anchor', 'attachments']
        if not all(field in body for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        # Extract and scan content
        urls = extract_urls_from_email(body['anchor'])
        threats = scan_urls_for_malicious_content(urls)

        files = extract_files_from_email(body['attachments'])
        file_threats = scan_files_for_malicious_content(files)

        # AI analysis
        prompt = generate_analysis_prompt(
            body['sender'],
            body['title'],
            body['body']
        )
        analysis = analyze_with_openai(prompt)
        sentiment = analyze_sentiment(analysis)

        # Prepare response
        response_data = {
            'analysis': analysis,
            'sentiment': sentiment,
            'urlThreats': threats,
            'fileThreats': file_threats,
            'processingTime': round(time.perf_counter() - start_time, 2)
        }

        return jsonify(response_data)

    except Exception as e:
        print(f"Analysis error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=config.getboolean('FLASK', 'DEBUG'))
