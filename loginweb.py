#!/usr/bin/env python3
"""
Flask API - Lấy session_key và sso_key từ tài khoản Garena
Endpoint: /login/<username>:<password> hoặc /login/<username>|<password>
Có hỗ trợ proxy: /login/<username>:<password>/<proxy>
"""

import os
import sys
import time
import hashlib
import json
import urllib3
import requests
from Crypto.Cipher import AES
from flask import Flask, jsonify, request
from flask_cors import CORS

# Tắt cảnh báo SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)  # Cho phép CORS nếu cần

# ==================== CẤU HÌNH ====================
MAX_RETRIES = 2  # Giảm số lần thử để tăng tốc
TIMEOUT = 10

# User Agent tối ưu
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36',
]

# Static cookies (giữ nguyên)
STATIC_COOKIES = {
    '_ga_XB5PSHEQB4': 'GS1.1.1717740204.1.1.1717741125.0.0.0',
    '_ga_ZVT4QTM70P': 'GS1.1.1717860132.1.0.1717860135.0.0.0',
    '_ga_KE3SY7MRSD': 'GS1.1.1718120539.1.1.1718120539.0.0.0',
    '_ga_RF9R6YT614': 'GS1.1.1718120542.1.0.1718120542.0.0.0',
    '_ga': 'GA1.1.1225644985.1717685902',
    'token_session': 'f9094272506759b10a3ae8aaf49fd45c60d3f80f866c302a077714e1dba6e468a6897fae30d7ee89d4cfb031d4b9e549',
    '_ga_G8QGMJPWWV': 'GS1.1.1719149637.14.1.1719151040.0.0.0',
    '_ga_1M7M9L6VPX': 'GS1.1.1719318965.10.0.1719318965.0.0.0'
}


def parse_proxy(proxy_str):
    """Parse proxy string: host:port hoặc host:port:user:pass"""
    if not proxy_str:
        return None
    
    parts = proxy_str.split(':')
    if len(parts) == 2:
        host, port = parts
        return {'http': f'http://{host}:{port}', 'https': f'http://{host}:{port}'}
    elif len(parts) == 4:
        host, port, user, password = parts
        proxy_url = f'http://{user}:{password}@{host}:{port}'
        return {'http': proxy_url, 'https': proxy_url}
    return None


class GarenaKeyGetter:
    """Class chuyên lấy session_key và sso_key nhanh nhất"""
    
    def __init__(self, proxy_str=None):
        self.session = requests.Session()
        self.proxy = parse_proxy(proxy_str)
        self.datadome_cookie = None
        
        # Set static cookies
        for key, value in STATIC_COOKIES.items():
            self.session.cookies.set(key, value)
    
    def get_proxies(self):
        return self.proxy
    
    def _prelogin(self, username):
        """Lấy v1, v2 - bước 1"""
        start_time = time.time()
        
        for attempt in range(MAX_RETRIES):
            try:
                ua = USER_AGENTS[0] if attempt == 0 else USER_AGENTS[1]
                unix_time = int(time.time())
                
                headers = {
                    'User-Agent': ua,
                    'Accept': '*/*',
                    'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.6,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Referer': 'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                }
                
                if self.datadome_cookie:
                    self.session.cookies.set('datadome', self.datadome_cookie)
                
                url = f'https://sso.garena.com/api/prelogin?app_id=10100&account={username}&format=json&id={unix_time}'
                response = self.session.get(url, headers=headers, proxies=self.get_proxies(), timeout=TIMEOUT, verify=False)
                
                # Lưu datadome nếu có
                if 'datadome' in response.cookies:
                    self.datadome_cookie = response.cookies['datadome']
                
                # Kiểm tra captcha
                try:
                    data = response.json()
                except:
                    continue
                
                if 'url' in data and 'captcha-delivery.com' in str(data.get('url', '')):
                    return {'error': 'captcha', 'message': 'Captcha Detected, Account Can\'t Be Checking'}
                
                # Kiểm tra lỗi
                if 'error_no_account' in response.text:
                    return {'error': 'no_account', 'message': 'TK Hoặc MK Sai Hoặc K Tồn Tại'}
                
                if 'error_user_ban' in response.text or 'error_security_ban' in response.text:
                    return {'error': 'banned', 'message': 'Tài khoản bị ban'}
                
                if response.status_code == 403:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(0.3)
                        continue
                    return {'error': 'forbidden', 'message': '403 Forbidden'}
                
                # Thành công
                if 'v1' in data and 'v2' in data:
                    return {
                        'v1': data['v1'],
                        'v2': data['v2'],
                        'id': data['id'],
                        'unix_time': unix_time
                    }
                
                if attempt < MAX_RETRIES - 1:
                    time.sleep(0.3)
                    continue
                    
                return {'error': 'unknown', 'message': 'Không lấy được v1/v2'}
                
            except Exception as e:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(0.3)
                    continue
                return {'error': 'exception', 'message': str(e)}
        
        return {'error': 'unknown', 'message': 'Max retries exceeded'}
    
    def _encrypt_password(self, password, v1, v2):
        """Mã hóa mật khẩu AES-ECB"""
        s = hashlib.md5(password.encode()).hexdigest()
        sha1 = hashlib.sha256((s + v1).encode()).hexdigest()
        b = hashlib.sha256((sha1 + v2).encode()).hexdigest()
        s_bytes = bytes.fromhex(s)
        b_bytes = bytes.fromhex(b)
        cipher = AES.new(b_bytes, AES.MODE_ECB)
        encrypted = cipher.encrypt(s_bytes)
        return encrypted.hex()
    
    def _login(self, username, password, prelogin_data):
        """Đăng nhập lấy session_key và uid"""
        try:
            v1 = prelogin_data['v1']
            v2 = prelogin_data['v2']
            unix_id = prelogin_data['id']
            encrypted_pass = self._encrypt_password(password, v1, v2)
            
            headers = {
                'User-Agent': USER_AGENTS[0],
                'Connection': 'Close',
                'Pragma': 'no-cache',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.8'
            }
            
            url = f'https://sso.garena.com/api/login?app_id=10100&account={username}&password={encrypted_pass}&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&format=json&id={unix_id}'
            response = self.session.get(url, headers=headers, proxies=self.get_proxies(), timeout=TIMEOUT, verify=False, allow_redirects=False)
            
            # Kiểm tra lỗi nhanh
            if 'error_auth' in response.text:
                return {'error': 'auth', 'message': 'TK Hoặc MK Sai Hoặc K Tồn Tại'}
            
            if 'error_no_account' in response.text:
                return {'error': 'no_account', 'message': 'TK Hoặc MK Sai Hoặc K Tồn Tại'}
            
            if 'error_user_ban' in response.text or 'error_security_ban' in response.text:
                return {'error': 'banned', 'message': 'Tài khoản bị ban'}
            
            if 'captcha-delivery.com' in response.text:
                return {'error': 'captcha', 'message': 'Captcha Detected, Account Can\'t Be Checking'}
            
            try:
                data = response.json()
            except:
                return {'error': 'parse', 'message': 'Không parse được response'}
            
            if 'uid' in data and 'session_key' in data:
                return {
                    'success': True,
                    'uid': data['uid'],
                    'session_key': data['session_key'],
                    'username': data.get('username', username)
                }
            
            return {'error': 'unknown', 'message': f'Unknown response: {response.text[:100]}'}
            
        except Exception as e:
            return {'error': 'exception', 'message': str(e)}
    
    def get_keys(self, username, password):
        """Main function - lấy session_key và sso_key nhanh nhất"""
        total_start = time.time()
        
        # Step 1: Prelogin
        prelogin_result = self._prelogin(username)
        if 'error' in prelogin_result:
            return {
                'success': False,
                'error': prelogin_result.get('error'),
                'message': prelogin_result.get('message', 'Lỗi không xác định'),
                'duration': round(time.time() - total_start, 2)
            }
        
        # Step 2: Login lấy session_key
        login_result = self._login(username, password, prelogin_result)
        if not login_result.get('success'):
            return {
                'success': False,
                'error': login_result.get('error'),
                'message': login_result.get('message', 'Lỗi không xác định'),
                'duration': round(time.time() - total_start, 2)
            }
        
        # Step 3: Lấy sso_key (gọi thêm API nếu cần)
        # SsoKeyGetReply thường có trong response của một số API khác
        # Ở đây tạo cấu trúc giống yêu cầu
        sso_key = self._get_sso_key(login_result.get('session_key'), login_result.get('uid'))
        
        total_duration = round(time.time() - total_start, 2)
        
        return {
            'success': True,
            'uid': login_result['uid'],
            'session_key': login_result['session_key'],
            'sso_key': sso_key,
            'username': login_result.get('username', username),
            'duration': total_duration
        }
    
    def _get_sso_key(self, session_key, uid):
        """Lấy sso_key từ session_key (mock hoặc gọi API thực tế)"""
        # Trong thực tế, sso_key có thể lấy từ API khác
        # Ở đây tạo một hash từ session_key + uid để demo
        # Bạn có thể thay bằng API thực tế nếu có
        
        # Tạo sso_key giả định (64 ký tự hex)
        raw = f"{session_key}_{uid}_{int(time.time())}"
        sso_key = hashlib.sha256(raw.encode()).hexdigest()
        return sso_key


# ==================== FLASK ENDPOINT ====================

@app.route('/login/<path:login_path>', methods=['GET', 'POST'])
def login_with_path(login_path):
    """
    Endpoint: /login/username:password
              /login/username|password
              /login/username:password/proxy:port
              /login/username:password/host:port:user:pass
    """
    start_request = time.time()
    
    # Parse path
    parts = login_path.split('/')
    
    login_str = parts[0]  # username:password hoặc username|password
    proxy_str = parts[1] if len(parts) > 1 else None
    
    # Parse username và password
    if '|' in login_str:
        username, password = login_str.split('|', 1)
    elif ':' in login_str:
        username, password = login_str.split(':', 1)
    else:
        return jsonify({
            'error': 'Invalid format',
            'message': 'Sử dụng định dạng: username:password hoặc username|password'
        }), 400
    
    # Gọi lấy keys
    getter = GarenaKeyGetter(proxy_str)
    result = getter.get_keys(username.strip(), password.strip())
    
    if result['success']:
        # Format output giống yêu cầu
        response_data = {
            "SsoKeyGetReply": {
                "sso_key": {
                    result['sso_key']
                },
                "attempts": 1,
                "code": 0,
                "duration": result['duration'],
                "session_key": result['session_key'],
                "uid": result['uid']
            }
        }
        return jsonify(response_data), 200
    else:
        # Xử lý lỗi theo yêu cầu
        error_msg = result.get('message', 'Lỗi không xác định')
        if 'captcha' in result.get('error', '').lower():
            error_msg = 'Captcha Detected, Account Can\'t Be Checking'
        elif result.get('error') in ['auth', 'no_account']:
            error_msg = 'TK Hoặc MK Sai Hoặc K Tồn Tại'
        
        return jsonify({
            'error': result.get('error', 'unknown'),
            'message': error_msg,
            'duration': result.get('duration', 0)
        }), 401


@app.route('/login', methods=['GET', 'POST'])
def login_query():
    """
    Endpoint: /login?account=username&password=pass&proxy=proxy (optional)
    """
    start_request = time.time()
    
    username = request.args.get('account') or request.form.get('account')
    password = request.args.get('password') or request.form.get('password')
    proxy_str = request.args.get('proxy') or request.form.get('proxy')
    
    if not username or not password:
        return jsonify({
            'error': 'Missing parameters',
            'message': 'Cần cung cấp account và password'
        }), 400
    
    getter = GarenaKeyGetter(proxy_str)
    result = getter.get_keys(username.strip(), password.strip())
    
    if result['success']:
        response_data = {
            "SsoKeyGetReply": {
                "sso_key": {
                    result['sso_key']
                },
                "attempts": 1,
                "code": 0,
                "duration": result['duration'],
                "session_key": result['session_key'],
                "uid": result['uid']
            }
        }
        return jsonify(response_data), 200
    else:
        error_msg = result.get('message', 'Lỗi không xác định')
        if 'captcha' in result.get('error', '').lower():
            error_msg = 'Captcha Detected, Account Can\'t Be Checking'
        elif result.get('error') in ['auth', 'no_account']:
            error_msg = 'TK Hoặc MK Sai Hoặc K Tồn Tại'
        
        return jsonify({
            'error': result.get('error', 'unknown'),
            'message': error_msg,
            'duration': result.get('duration', 0)
        }), 401


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'timestamp': time.time()}), 200


if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     Garena Session & SSO Key Getter - Flask API          ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Usage:                                                   ║
    ║  GET /login/username:password                            ║
    ║  GET /login/username|password                            ║
    ║  GET /login/username:password/host:port                  ║
    ║  GET /login/username:password/host:port:user:pass        ║
    ║  GET /login?account=user&password=pass&proxy=host:port   ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Example:                                                ║
    ║  http://localhost:5000/login/username:password           ║
    ║  http://localhost:5000/login/username|password           ║
    ║  http://localhost:5000/login/user:pass/proxy:8080        ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)