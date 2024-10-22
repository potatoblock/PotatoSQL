import http.server
import json
import os
import sqlite3
import threading
from urllib.parse import urlparse, parse_qs
import base64

DB_FILENAME = 'kv.db'
CONFIG_FILENAME = 'config.json'
db_lock = threading.Lock()

# 确保数据库存在，并创建连接
def init_db():
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS kv_store (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# 读取配置文件
def read_config():
    with open(CONFIG_FILENAME, 'r') as config_file:
        return json.load(config_file)

config = read_config()
users = config['users']  # 获取用户字典
port = config['port']  # 获取端口

# 数据库操作
def db_add(key, value):
    with db_lock:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        cursor.execute('REPLACE INTO kv_store (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()

def db_delete(key):
    with db_lock:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM kv_store WHERE key = ?', (key,))
        conn.commit()
        conn.close()

def db_get(key):
    with db_lock:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM kv_store WHERE key = ?', (key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

def db_get_all():
    with db_lock:
        conn = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM kv_store')
        result = cursor.fetchall()
        conn.close()
        return {key: value for key, value in result}

# 身份验证
def authenticate(auth_header):
    if not auth_header or not auth_header.startswith("Basic "):
        return False

    auth_info = base64.b64decode(auth_header[6:]).decode('utf-8').split(':')
    if len(auth_info) != 2:
        return False

    username, password = auth_info
    return username in users and users[username] == password

# 处理HTTP请求
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        query_params = parse_qs(url.query)

        # 身份验证
        auth_header = self.headers.get('Authorization')
        if not authenticate(auth_header):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        # 根据请求路径处理
        if url.path == '/get':
            key = query_params.get('key', [None])[0]
            if key:
                value = db_get(key)
                if value is not None:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({key: value}).encode())
                else:
                    self.send_error(404, "Key not found")
            else:
                self.send_error(400, "Key parameter is missing")

        elif url.path == '/data':
            all_data = db_get_all()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(all_data).encode())

        else:
            self.send_error(404, "Endpoint not found")

    def do_POST(self):
        # 身份验证
        auth_header = self.headers.get('Authorization')
        if not authenticate(auth_header):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        # 获取请求头中的 Content-Length
        content_length = int(self.headers['Content-Length'])
        url = urlparse(self.path)
        post_data = json.loads(self.rfile.read(content_length))

        if url.path == '/set':
            key = post_data.get('key')
            value = post_data.get('value')
            if key and value:
                db_add(key, value)
                self.send_response(201)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Data set successfully'}).encode())
            else:
                self.send_error(400, "Key or value is missing")
        
        elif url.path == '/delete':
            key = post_data.get('key')
            if key:
                db_delete(key)
                self.send_response(202)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'message': 'Data deletion successful'}).encode())
            else:
                self.send_error(400, "Key is missing")

        elif url.path == '/sql':
            sql_query = post_data.get('query')
            if sql_query:
                try:
                    with db_lock:
                        conn = sqlite3.connect(DB_FILENAME)
                        cursor = conn.cursor()
                        cursor.execute(sql_query)
                        result = cursor.fetchall()
                        conn.commit()
                        conn.close()

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'result': result}).encode())

                except Exception as e:
                    self.send_error(400, f"SQL Error: {str(e)}")
            else:
                self.send_error(400, "Query parameter is missing")

        else:
            self.send_error(404, "Endpoint not found")

# 设置HTTP服务器
handler = RequestHandler
httpd = http.server.HTTPServer(("", port), handler)

print(f"Serving HTTP on port {port}")
httpd.serve_forever()
