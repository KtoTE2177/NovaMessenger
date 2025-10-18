import json
import sqlite3
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import jwt
import hashlib
import os

SECRET_KEY = "super-secret-key-for-modern-messenger-2025"

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('messenger.db', check_same_thread=False)
        self.conn.execute('PRAGMA encoding="UTF-8";')
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                reply_to_id INTEGER DEFAULT NULL,
                is_favorite INTEGER DEFAULT 0
            )
        ''')
        
        # Добавляем столбец reply_to_id, если его нет
        try:
            cursor.execute('ALTER TABLE messages ADD COLUMN reply_to_id INTEGER DEFAULT NULL')
        except sqlite3.OperationalError:
            pass

        # Добавляем столбец is_favorite, если его нет
        try:
            cursor.execute('ALTER TABLE messages ADD COLUMN is_favorite INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass

        # Добавляем столбец avatar в таблицу users, если его нет
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT NULL')
        except sqlite3.OperationalError:
            pass
        
        # Добавляем столбец about_me в таблицу users, если его нет
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN about_me TEXT DEFAULT NULL')
        except sqlite3.OperationalError:
            pass

        # Добавляем столбец avatar в таблицу messages, если его нет
        try:
            cursor.execute('ALTER TABLE messages ADD COLUMN avatar TEXT DEFAULT NULL')
        except sqlite3.OperationalError:
            pass

        self.conn.commit()

    def add_user_with_avatar(self, username: str, password_hash: str, avatar: str = None, about_me: str = None) -> bool:
        try:
            cursor = self.conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash, avatar, about_me) VALUES (?, ?, ?, ?)', 
                          (username, password_hash, avatar, about_me))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str):
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, username, password_hash, created_at, avatar, about_me FROM users WHERE username = ?', (username,))
        return cursor.fetchone()

    def add_message_with_avatar(self, username: str, text: str, avatar: str, reply_to_id: int = None) -> int:
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO messages (username, text, avatar, reply_to_id) VALUES (?, ?, ?, ?)', 
                      (username, text, avatar, reply_to_id))
        self.conn.commit()
        return cursor.lastrowid

    def update_user_profile(self, username: str, avatar: str = None, about_me: str = None) -> bool:
        cursor = self.conn.cursor()
        updates = []
        params = []

        if avatar is not None:
            updates.append("avatar = ?")
            params.append(avatar)
        if about_me is not None:
            updates.append("about_me = ?")
            params.append(about_me)

        if not updates:
            return False

        query = f"UPDATE users SET {', '.join(updates)} WHERE username = ?"
        params.append(username)

        cursor.execute(query, tuple(params))
        self.conn.commit()
        return cursor.rowcount > 0

    def update_message_favorite_status(self, message_id: int, is_favorite: bool) -> bool:
        cursor = self.conn.cursor()
        cursor.execute('UPDATE messages SET is_favorite = ? WHERE id = ?', 
                      (1 if is_favorite else 0, message_id))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_messages(self, username: str, only_favorites: bool = False, limit: int = 100) -> list:
        cursor = self.conn.cursor()
        
        query = """
            SELECT 
                m.id, m.username, m.text, m.timestamp, m.reply_to_id, m.is_favorite,
                r.username AS reply_username, r.text AS reply_text, m.avatar
            FROM messages m
            LEFT JOIN messages r ON m.reply_to_id = r.id
            WHERE m.username = ?
        """
        params = [username]
        
        if only_favorites:
            query += " AND m.is_favorite = 1"

        query += " ORDER BY m.timestamp ASC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, tuple(params))
        return cursor.fetchall()

    def get_favorite_messages_for_user(self, username: str, limit: int = 100) -> list:
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT
                m.id, m.username, m.text, m.timestamp, m.reply_to_id, m.is_favorite,
                r.username AS reply_username, r.text AS reply_text, m.avatar
            FROM messages m
            LEFT JOIN messages r ON m.reply_to_id = r.id
            WHERE m.username = ? AND m.is_favorite = 1
            ORDER BY m.timestamp ASC
            LIMIT ?
        ''', (username, limit))
        return cursor.fetchall()

    def update_message_text(self, message_id: int, new_text: str, username: str) -> str | None:
        cursor = self.conn.cursor()
        cursor.execute('SELECT username FROM messages WHERE id = ?', (message_id,))
        message_owner = cursor.fetchone()
        if not message_owner or message_owner[0] != username:
            return None
        
        edited_timestamp = datetime.now().isoformat()
        cursor.execute('UPDATE messages SET text = ?, timestamp = ? WHERE id = ?', 
                      (new_text, edited_timestamp, message_id))
        self.conn.commit()
        return edited_timestamp if cursor.rowcount > 0 else None

    def search_users(self, search_term: str, limit: int = 10) -> list:
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT username, avatar, about_me FROM users 
            WHERE username LIKE ? 
            LIMIT ?
        ''', (f'{search_term}%', limit))
        return cursor.fetchall()

db = Database()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username: str) -> str:
    payload = {'username': username}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['username']
    except jwt.InvalidTokenError:
        return None

class HTTPHandler(BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    
    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        print(f"do_GET: Path received: {self.path}")
        if self.path == '/':
            self.serve_file('index.html', 'text/html')
        elif self.path == '/style.css':
            self.serve_file('style.css', 'text/css')
        elif self.path == '/script.js':
            self.serve_file('script.js', 'application/javascript')
        elif self.path == '/websocket_test.html':
            self.serve_file('websocket_test.html', 'text/html')
        elif self.path == '/messages':
            self.handle_get_messages()
        elif self.path == '/messages/favorites':
            self.handle_get_favorite_messages()
        elif self.path.startswith('/user/profile'):
            self.handle_get_user_profile()
        elif self.path.startswith('/users/search'):
            self.handle_search_users()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/register':
            self.handle_register()
        elif self.path == '/login':
            self.handle_login()
        elif self.path == '/message/favorite':
            self.handle_favorite_message()
        elif self.path == '/message/edit':
            self.handle_edit_message()
        elif self.path == '/user/profile/update':
            self.handle_update_profile()
        elif self.path == '/message/send':  # ДОБАВЛЕНО: для отправки сообщений через HTTP
            self.handle_send_message()
        else:
            self.send_error(404)

    def serve_file(self, filename: str, content_type: str):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read().encode('utf-8')
            
            self.send_response(200)
            self.send_header('Content-type', f'{content_type}; charset=utf-8')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)
        except Exception as e:
            print(f"Error serving file {filename}: {e}")
            self.send_error(500)

    def handle_register(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        avatar = data.get('avatar', None)
        about_me = data.get('aboutMe', None)

        if not username or not password:
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False, 
                'message': 'Заполните все поля'
            }).encode())
            return
        
        password_hash = hash_password(password)
        
        if db.add_user_with_avatar(username, password_hash, avatar, about_me):
            self.send_response(200)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': True,
                'message': 'Регистрация успешна'
            }).encode())
        else:
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False, 
                'message': 'Пользователь уже существует'
            }).encode())

    def handle_login(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        user_data = db.get_user(username)
        if user_data and user_data[2] == hash_password(password):
            token = create_token(username)
            self.send_response(200)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': True,
                'token': token,
                'user': {'username': username, 'avatar': user_data[4], 'aboutMe': user_data[5]}
            }).encode())
        else:
            self.send_response(401)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False, 
                'message': 'Неверные данные для входа'
            }).encode())

    def handle_send_message(self):  # НОВЫЙ МЕТОД: отправка сообщений через HTTP
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            token = None
        
        username = verify_token(token) if token else None
        
        if not username:
            self.send_response(401)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Неавторизованный доступ'
            }).encode())
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data)
            text = data.get('text', '').strip()
            avatar = data.get('avatar', None)
            reply_to_id = data.get('replyToId')
        except (json.JSONDecodeError, TypeError):
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Некорректный запрос'}).encode())
            return

        if not text:
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Сообщение не может быть пустым'}).encode())
            return

        message_id = db.add_message_with_avatar(username, text, avatar, reply_to_id)
        
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({
            'success': True,
            'message': 'Сообщение отправлено',
            'messageId': message_id
        }).encode())

    def handle_favorite_message(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            token = None
        
        username = verify_token(token) if token else None
        
        if not username:
            self.send_response(401)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Неавторизованный доступ'
            }).encode())
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data)
            message_id = data.get('messageId')
            is_favorite = data.get('isFavorite')
        except (json.JSONDecodeError, TypeError):
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Некорректный запрос'}).encode())
            return

        if db.update_message_favorite_status(message_id, is_favorite):
            self.send_response(200)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'message': 'Статус избранного обновлен'}).encode())
        else:
            self.send_response(500)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Не удалось обновить статус избранного'}).encode())

    def handle_get_messages(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            token = None
        
        username = verify_token(token) if token else None
        
        if not username:
            self.send_response(401)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Неавторизованный доступ'
            }).encode())
            return
        
        messages = db.get_messages(username=username)
        formatted_messages = [
            {
                'id': msg[0],
                'username': msg[1],
                'text': msg[2],
                'timestamp': msg[3],
                'replyToId': msg[4],
                'isFavorite': bool(msg[5]),
                'replyToUsername': msg[6] if msg[6] else None,
                'replyToText': msg[7] if msg[7] else None,
                'avatar': msg[8]
            }
            for msg in messages
        ]
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(formatted_messages).encode())

    def handle_get_favorite_messages(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            token = None
        
        username = verify_token(token) if token else None
        
        if not username:
            self.send_response(401)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Неавторизованный доступ'
            }).encode())
            return
        
        messages = db.get_favorite_messages_for_user(username=username)
        formatted_messages = [
            {
                'id': msg[0],
                'username': msg[1],
                'text': msg[2],
                'timestamp': msg[3],
                'replyToId': msg[4],
                'isFavorite': bool(msg[5]),
                'replyToUsername': msg[6] if msg[6] else None,
                'replyToText': msg[7] if msg[7] else None,
                'avatar': msg[8]
            }
            for msg in messages
        ]
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(formatted_messages).encode())

    def handle_get_user_profile(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        target_username = query_params.get('username', [None])[0]

        if not target_username:
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Не указано имя пользователя'}).encode())
            return

        user_data = db.get_user(target_username)

        if user_data:
            profile_info = {
                'username': user_data[1],
                'avatar': user_data[4] if user_data[4] else None,
                'aboutMe': user_data[5] if user_data[5] else None,
            }
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(profile_info).encode())
        else:
            self.send_response(404)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Пользователь не найден'}).encode())

    def handle_search_users(self):
        search_term = parse_qs(urlparse(self.path).query).get('username', [''])[0]
        if not search_term:
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Не указан поисковый запрос'}).encode())
            return

        users = db.search_users(search_term)
        formatted_users = [
            {
                'username': user[0],
                'avatar': user[1] if user[1] else None,
                'aboutMe': user[2] if user[2] else None
            }
            for user in users
        ]

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(formatted_users).encode())

    def handle_edit_message(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            token = None
        
        username = verify_token(token) if token else None
        
        if not username:
            self.send_response(401)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Неавторизованный доступ'
            }).encode())
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data)
            message_id = data.get('messageId')
            new_text = data.get('newText', '').strip()
        except (json.JSONDecodeError, TypeError):
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Некорректный запрос'}).encode())
            return

        if not isinstance(message_id, int) or not new_text:
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Некорректные данные'}).encode())
            return
        
        edited_timestamp = db.update_message_text(message_id, new_text, username)
        
        if edited_timestamp:
            self.send_response(200)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'message': 'Сообщение обновлено', 'editedTimestamp': edited_timestamp}).encode())
        else:
            self.send_response(403)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Невозможно обновить сообщение'}).encode())

    def handle_update_profile(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            token = None
        
        username = verify_token(token) if token else None
        
        if not username:
            self.send_response(401)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Неавторизованный доступ'
            }).encode())
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data)
            avatar = data.get('avatar', None)
            about_me = data.get('aboutMe', None)
        except json.JSONDecodeError:
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Некорректный запрос'
            }).encode())
            return
        
        if db.update_user_profile(username, avatar, about_me):
            user_data = db.get_user(username)
            if user_data:
                updated_user = {
                    'username': user_data[1],
                    'avatar': user_data[4],
                    'aboutMe': user_data[5]
                }
                
                self.send_response(200)
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    'success': True,
                    'message': 'Профиль успешно обновлен',
                    'user': updated_user
                }).encode())
            else:
                self.send_response(500)
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    'success': False,
                    'message': 'Ошибка при получении обновленных данных'
                }).encode())
        else:
            self.send_response(500)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Не удалось обновить профиль'
            }).encode())

def run_http_server():
    """Запуск HTTP сервера"""
    port = int(os.environ.get("PORT", 8000))
    server = HTTPServer(('0.0.0.0', port), HTTPHandler)
    print(f"HTTP сервер запущен на порту {port}")
    print("Мессенджер готов к работе!")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Сервер остановлен")
    except Exception as e:
        print(f"Ошибка сервера: {e}")

if __name__ == '__main__':
    print("Запуск HTTP мессенджера...")
    print("=" * 50)
    run_http_server()

