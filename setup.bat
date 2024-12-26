@echo off
REM setup.bat - Flaskアプリケーションのセットアップスクリプト（Windows用）

REM 管理者権限で実行されているか確認
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo 管理者権限が必要です。再実行します...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM Pythonとpipのバージョンを確認
python --version
pip --version

REM 仮想環境の作成と有効化
python -m venv venv
call venv\Scripts\activate

REM 必要なライブラリのインストール
pip install Flask requests python-dotenv pyotp qrcode

REM .envファイルの作成
echo GITHUB_CLIENT_ID=your_github_client_id> .env
echo GITHUB_CLIENT_SECRET=your_github_client_secret>> .env
echo RESEND_API_KEY=your_resend_api_key>> .env
echo FROM_EMAIL=no-reply@your-domain.com>> .env

REM Certbotのダウンロードとインストール
if not exist certbot (
    mkdir certbot
)
cd certbot
if not exist certbot-beta-installer-win32.exe (
    powershell -Command "Invoke-WebRequest -Uri https://dl.eff.org/certbot-beta-installer-win32.exe -OutFile certbot-beta-installer-win32.exe"
)
certbot-beta-installer-win32.exe

REM Certbotを使用してLet's Encrypt証明書を取得
certbot certonly --standalone -d your-domain.com -d www.your-domain.com

echo Setup complete. Run "call venv\Scripts\activate" to activate the virtual environment.
