#!/bin/bash
# setup.sh - Flaskアプリケーションのセットアップスクリプト（Linux/Mac用）

# Pythonとpipのバージョンを確認
python3 --version
pip3 --version

# 仮想環境の作成と有効化
python3 -m venv venv
source venv/bin/activate

# 必要なライブラリのインストール
pip install Flask requests python-dotenv pyotp qrcode

# .envファイルの作成
echo "GITHUB_CLIENT_ID=your_github_client_id" > .env
echo "GITHUB_CLIENT_SECRET=your_github_client_secret" >> .env
echo "RESEND_API_KEY=your_resend_api_key" >> .env
echo "FROM_EMAIL=no-reply@your-domain.com" >> .env

# Certbotのインストールと証明書の取得
sudo apt update
sudo apt install -y certbot
sudo certbot certonly --standalone -d your-domain.com -d www.your-domain.com

echo "Setup complete. Run 'source venv/bin/activate' to activate the virtual environment."
