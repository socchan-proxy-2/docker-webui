from flask import Flask, redirect, url_for, session, request, render_template_string
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

# GitHub OAuth設定
CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
AUTHORIZATION_BASE_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'
USER_API_URL = 'https://api.github.com/user'

# Resend設定
RESEND_API_KEY = os.getenv('RESEND_API_KEY')
FROM_EMAIL = os.getenv('FROM_EMAIL')

def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return buf

@app.route('/')
def home():
    return 'Welcome! <a href="/login">Login with GitHub</a>'

@app.route('/login')
def login():
    params = {
        'client_id': CLIENT_ID,
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
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
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
        "from": FROM_EMAIL,
        "to": to_email,
        "subject": "Your 2FA verification code",
        "text": f"Your verification code is: {otp}"
    }

    try:
        response = requests.post(
            "https://api.resend.io/v1/email/send",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
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
