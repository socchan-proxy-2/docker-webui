from flask import Flask, redirect, url_for, session, request, render_template_string, flash
import requests
from urllib.parse import urlencode
import os
import pyotp
import qrcode
import io
from dotenv import load_dotenv
import base64

# .envファイルから環境変数を読み込む
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 環境変数を格納するファイルのパス
ENV_FILE_PATH = '.env'

def save_env_variables(variables):
    with open(ENV_FILE_PATH, 'w') as env_file:
        for key, value in variables.items():
            env_file.write(f"{key}={value}\n")

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        github_client_id = request.form['github_client_id']
        github_client_secret = request.form['github_client_secret']
        resend_api_key = request.form['resend_api_key']
        from_email = request.form['from_email']

        # 環境変数を保存
        env_variables = {
            'GITHUB_CLIENT_ID': github_client_id,
            'GITHUB_CLIENT_SECRET': github_client_secret,
            'RESEND_API_KEY': resend_api_key,
            'FROM_EMAIL': from_email
        }
        save_env_variables(env_variables)

        # 環境変数を再読み込み
        load_dotenv()

        flash('Settings updated successfully!')
        return redirect(url_for('home'))

    return render_template_string('''
    <h1>Settings</h1>
    <form method="post">
        <label for="github_client_id">GitHub Client ID:</label><br>
        <input type="text" id="github_client_id" name="github_client_id"><br><br>
        <label for="github_client_secret">GitHub Client Secret:</label><br>
        <input type="text" id="github_client_secret" name="github_client_secret"><br><br>
        <label for="resend_api_key">Resend API Key:</label><br>
        <input type="text" id="resend_api_key" name="resend_api_key"><br><br>
        <label for="from_email">From Email:</label><br>
        <input type="email" id="from_email" name="from_email"><br><br>
        <input type="submit" value="Save">
    </form>
    ''')

@app.route('/')
def home():
    if not os.getenv('GITHUB_CLIENT_ID') or not os.getenv('GITHUB_CLIENT_SECRET') or not os.getenv('RESEND_API_KEY') or not os.getenv('FROM_EMAIL'):
        return redirect(url_for('settings'))
    return 'Welcome! <a href="/login">Login with GitHub</a>'

@app.route('/login')
def login():
    params = {
        'client_id': os.getenv('GITHUB_CLIENT_ID'),
        'redirect_uri': url_for('callback', _external=True),
        'scope': 'user:email',
        'state': os.urandom(8).hex()
    }
    url = f"{AUTHORIZATION_BASE_URL}?{urlencode(params)}"
    return redirect(url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')

    token_response = requests.post(
        TOKEN_URL,
        headers={'Accept': 'application/json'},
        data={
            'client_id': os.getenv('GITHUB_CLIENT_ID'),
            'client_secret': os.getenv('GITHUB_CLIENT_SECRET'),
            'code': code,
            'redirect_uri': url_for('callback', _external=True),
            'state': state
        }
    )
    token_response_data = token_response.json()
    access_token = token_response_data['access_token']

    user_response = requests.get(
        USER_API_URL,
        headers={'Authorization': f'token {access_token}'}
    )
    user_data = user_response.json()

    session['user'] = user_data

    # 2FAのセットアップ
    if '2fa_secret' not in session:
        session['2fa_secret'] = pyotp.random_base32()
    
    return redirect(url_for('verify_2fa'))

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST' and 'skip_2fa' in request.form:
        session['2fa_verified'] = True
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(session['2fa_secret'])
        if totp.verify(otp):
            session['2fa_verified'] = True
            send_2fa_verification_email(session['user']['email'], totp.now())
            return redirect(url_for('profile'))
        else:
            return 'Invalid OTP, try again.'

    totp = pyotp.TOTP(session['2fa_secret'])
    otp_uri = totp.provisioning_uri(session['user']['login'], issuer_name="YourAppName")
    qr_code_img = generate_qr_code(otp_uri)
    
    template = """
    <h1>Verify 2FA</h1>
    <p>Scan the QR code with your Authenticator app and enter the OTP:</p>
    <img src="data:image/png;base64,{{ qr_code_img }}" alt="QR Code"/>
    <form method="post">
        <input type="text" name="otp" placeholder="Enter OTP"/>
        <input type="submit" value="Verify"/>
    </form>
    <form method="post">
        <input type="hidden" name="skip_2fa" value="true"/>
        <input type="submit" value="Skip 2FA"/>
    </form>
    """
    qr_code_img_b64 = base64.b64encode(qr_code_img.getvalue()).decode('utf-8')

    return render_template_string(template, qr_code_img=qr_code_img_b64)

def send_2fa_verification_email(to_email, otp):
    email_data = {
        "from": os.getenv('FROM_EMAIL'),
        "to": to_email,
        "subject": "Your 2FA verification code",
        "text": f"Your verification code is: {otp}"
    }

    try:
        response = requests.post(
            "https://api.resend.io/v1/email/send",
            headers={
                "Authorization": f"Bearer {os.getenv('RESEND_API_KEY')}",
                "Content-Type": "application/json"
            },
            json=email_data
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'Failed to send email: {str(e)}')

@app.route('/profile')
def profile():
    if '2fa_verified' in session and session['2fa_verified']:
        user = session['user']
        return f"Logged in as {user['login']}<br><a href='/logout'>Logout</a>"
    else:
        return redirect(url_for('verify_2fa'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
