import datetime
import os
from flask import Flask, jsonify, request
from flask_cors import CORS # type: ignore
import requests

# Initialize the Flask application
app = Flask(__name__)
# Enable Cross-Origin Resource Sharing (CORS) to allow the frontend to connect
CORS(app)

# --- Configuration ---
# IMPORTANT: You need a free API key from VirusTotal for this to work.
# 1. Go to https://www.virustotal.com/ and create a free account.
# 2. Find your API key in your profile section.
# 3. It's best practice to set this as an environment variable.
#    Alternatively, you can paste it directly here for simplicity during the hackathon.
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '918b34be1ec034177d85c07fcb2c8153c41f94e417ee615cee7c22cc5a4f0956')
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

@app.route('/api/analyze', methods=['POST'])
def analyze_ip():
    """
    API endpoint that receives an IP address, analyzes it using the VirusTotal API,
    and returns a structured threat assessment.
    """
    # 1. Get the IP address from the incoming POST request
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'error': 'IP address not provided'}), 400
    
    ip_address = data['ip']

    # 2. Prepare and make the request to the VirusTotal API
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(f"{VIRUSTOTAL_API_URL}{ip_address}", headers=headers)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        vt_data = response.json()

        # 3. Interpret the analysis results from VirusTotal
        stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        threat_type = 'CLEAN' # Default type
        info = f"{malicious} vendors flagged this IP as malicious."

        if malicious > 5:
            threat_type = 'BLOCK'
            info = f"High-confidence threat: {malicious} vendors flagged as malicious."
        elif malicious > 0:
            threat_type = 'MALWARE'
            info = f"Potential threat: {malicious} vendors flagged as malicious."
        elif suspicious > 0:
            threat_type = 'ANOMALY'
            info = f"Suspicious activity detected by {suspicious} vendors."
        else:
            info = "IP appears clean based on VirusTotal analysis."

        # 4. Construct the response object for our frontend
        analysis_result = {
            'type': threat_type,
            'ip': ip_address,
            'info': info,
            'details': stats, # Include the full stats for potential frontend use
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return jsonify(analysis_result)

    except requests.exceptions.HTTPError as err:
        if err.response.status_code == 404:
             return jsonify({'error': f"IP address {ip_address} not found in VirusTotal."}), 404
        else:
             return jsonify({'error': f"API Error: {err}"}), 500
    except Exception as e:
        return jsonify({'error': f"An unexpected error occurred: {e}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
