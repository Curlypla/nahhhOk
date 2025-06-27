import requests,time, json, os, random, base64
from flask import Flask, redirect, request, session, url_for
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

def base64_decode(encoded_str):
    """Décoder une chaîne encodée en base64, en gérant les éventuels caractères de remplissage"""
    padding = '=' * (-len(encoded_str) % 4)
    return base64.b64decode(encoded_str + padding).decode('utf-8')

def base64_encode(data):
    """Encoder une chaîne en base64, en ajoutant les caractères de remplissage nécessaires"""
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    return encoded_bytes.decode('utf-8').rstrip('=')  # Retirer les caractères de remplissage '=' pour correspondre à l'encodage attendu

CLIENT_ID = base64_decode("NjgxMjU1ODA5Mzk1LW9vOGZ0Mm9wcmRybnA5ZTNhcWY2YXYzaG1kaWIxMzVqLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t")
CLIENT_SECRET = base64_decode("R09DU1BYLTR1SGdNUG0tMW83U2stZ2VWNkN1NWNsWEZzeGw=")
TOKEN_URI = "https://oauth2.googleapis.com/token"
API_URL = base64_decode("aHR0cHM6Ly9jbG91ZGNvZGUtcGEuZ29vZ2xlYXBpcy5jb20vdjFpbnRlcm5hbDpnZW5lcmF0ZUNvbnRlbnQ=")

def cache_token(duration_minutes=30):
    """Décorateur pour mettre en cache le token d'accès pendant une durée donnée"""
    def decorator(func):
        func._cache = {}
        @wraps(func)
        def wrapper(acc_token):
            current_time = time.time()
            if acc_token in func._cache:
                cached_token, cached_time = func._cache[acc_token]
                if current_time - cached_time < duration_minutes * 60:
                    return cached_token
            result = func(acc_token)
            func._cache[acc_token] = (result, current_time)
            return result
        return wrapper
    return decorator

accounts = json.loads(base64_decode(os.environ.get("KEYS", "{}")))


@cache_token(duration_minutes=30)
def get_new_access_token(acc_token):
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': acc_token,
        'grant_type': 'refresh_token'
    }
    response = requests.post(TOKEN_URI, data=payload)
    new_token_data = response.json()
    return new_token_data['access_token']

def api_request(prompt, project_id, access_token, model_name):
    prompt = prompt.replace("Be meticulous in removing all watermarks and site links.", "Be meticulous in removing all watermarks and site links, while trying to recover, if present, the original text without the watermarks or site links.")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "User-Agent": "GeminiCLI/0.1.1 (win32; x64) google-api-nodejs-client/9.15.1",
        "x-goog-api-client": "gl-node/20.16.0",
        "Host": "cloudcode-pa.googleapis.com",
    }

    request_body = {
        "model": model_name,
        "project": project_id,
        "request": {
            "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }]
        }
    }
    rdmProxy = requests.get("http://mw084wsk0os0so0gwsowcwkk.147.160.139.148.sslip.io/getproxy").json()
    proxy_ip = rdmProxy["proxy"]["ip"]
    proxy_url = rdmProxy["proxy"]["url"]
    proxies = {
        "http": f"http://{proxy_url}",
        "https": f"https://{proxy_url}"
    }
    response = requests.post(API_URL, headers=headers, json=request_body, timeout=60*7, proxies=proxies).json()
    print(str(response)[:150])
    result = response["response"]["candidates"][0]["content"]["parts"][0]["text"]
    return result

@app.route('/')
def index():
    return "yey"

@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()
    prompt = data.get('prompt')

    if not prompt:
        return "Prompt is required", 400

    random_key = random.choice(list(accounts.keys()))
    account = accounts[random_key]

    print(f"Using account: {account}")
    access_token = get_new_access_token(account['refresh_token'])
    if not access_token:
        return "Failed to obtain access token", 500
    
    try:
        result = api_request(prompt, account['project_id'], access_token, model_name="gemini-2.5-pro")
        return {"response": result}
    except Exception as e:
        try:
            result = api_request(prompt, account['project_id'], access_token, model_name="gemini-2.5-flash")
            return {"response": result}
        except Exception as e2:
            return "Failed to generate content", 500

if __name__ == '__main__':
    app.run(port=2222, debug=True)
