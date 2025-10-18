import asyncio
import websockets
import json
import sqlite3
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import jwt
import hashlib
import threading
from typing import Dict, Any, Set
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
                is_favorite INTEGER DEFAULT 0 -- Добавляем столбец для избранных сообщений
            )
        ''')
        
        # Добавляем столбец reply_to_id, если его нет
        try:
            cursor.execute('ALTER TABLE messages ADD COLUMN reply_to_id INTEGER DEFAULT NULL')
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                raise

        # Добавляем столбец is_favorite, если его нет
        try:
            cursor.execute('ALTER TABLE messages ADD COLUMN is_favorite INTEGER DEFAULT 0')
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                raise

        # Добавляем столбец avatar в таблицу users, если его нет
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT NULL')
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                raise
        
        # Добавляем столбец about_me в таблицу users, если его нет
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN about_me TEXT DEFAULT NULL')
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                raise

        # Добавляем столбец avatar в таблицу messages, если его нет
        try:
            cursor.execute('ALTER TABLE messages ADD COLUMN avatar TEXT DEFAULT NULL')
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                raise

        # Добавляем таблицу для личных сообщений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS private_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_username TEXT NOT NULL,
                receiver_username TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                reply_to_id INTEGER DEFAULT NULL,
                avatar TEXT DEFAULT NULL,
                FOREIGN KEY (sender_username) REFERENCES users (username),
                FOREIGN KEY (receiver_username) REFERENCES users (username)
            )
        ''')
        self.conn.commit()

    def add_user(self, username: str, password_hash: str) -> bool:
        try:
            cursor = self.conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                          (username, password_hash))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    # Новая функция для добавления пользователя с аватаром и описанием о себе
    def add_user_with_avatar(self, username: str, password_hash: str, avatar: str = None, about_me: str = None) -> bool:
        try:
            cursor = self.conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash, avatar, about_me) VALUES (?, ?, ?, ?)', 
                          (username, password_hash, avatar, about_me))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> Any:
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, username, password_hash, created_at, avatar, about_me FROM users WHERE username = ?', (username,))
        return cursor.fetchone()

    def add_message(self, username: str, text: str, reply_to_id: int = None) -> int:
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO messages (username, text, reply_to_id) VALUES (?, ?, ?)', 
                      (username, text, reply_to_id))
        self.conn.commit()
        return cursor.lastrowid

    # Обновляем add_message для сохранения аватара
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
            return False # Ничего для обновления

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
        """
        conditions = ["m.username = ?"]
        params = [username]
        
        if only_favorites:
            conditions.append("m.is_favorite = 1")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY m.timestamp ASC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, tuple(params))
        raw_messages = cursor.fetchall()
        print(f"Database.get_messages: Raw messages from DB (tuples): {raw_messages}") # ДОБАВЛЕНО ДЛЯ ОТЛАДКИ
        return raw_messages

    def get_favorite_messages_for_user(self, username: str, limit: int = 100) -> list:
        cursor = self.conn.cursor();
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
        raw_messages = cursor.fetchall()
        print(f"Database.get_favorite_messages_for_user: Raw messages from DB (tuples): {raw_messages}")
        return raw_messages

    def update_message_text(self, message_id: int, new_text: str, username: str) -> str | None:
        cursor = self.conn.cursor()
        # Проверяем, что сообщение принадлежит пользователю, который его редактирует
        cursor.execute('SELECT username FROM messages WHERE id = ?', (message_id,))
        message_owner = cursor.fetchone()
        if not message_owner or message_owner[0] != username:
            return None # Пользователь не является владельцем сообщения или сообщение не найдено
        
        edited_timestamp = datetime.now().isoformat() # Генерируем новое время изменения
        cursor.execute('UPDATE messages SET text = ?, timestamp = ? WHERE id = ?', 
                      (new_text, edited_timestamp, message_id))
        self.conn.commit()
        return edited_timestamp if cursor.rowcount > 0 else None

    # Новый метод для поиска пользователей
    def search_users(self, search_term: str, limit: int = 10) -> list:
        cursor = self.conn.cursor()
        # Ищем пользователей, чьи имена начинаются с search_term
        cursor.execute('''
            SELECT username, avatar, about_me FROM users 
            WHERE username LIKE ? 
            LIMIT ?
        ''', (f'{search_term}%', limit))
        return cursor.fetchall()

    # Новый метод для добавления личного сообщения
    def add_private_message(self, sender_username: str, receiver_username: str, text: str, avatar: str = None, reply_to_id: int = None) -> int:
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO private_messages (sender_username, receiver_username, text, avatar, reply_to_id) VALUES (?, ?, ?, ?, ?)', 
                      (sender_username, receiver_username, text, avatar, reply_to_id))
        self.conn.commit()
        return cursor.lastrowid

    # Новый метод для получения личных сообщений между двумя пользователями
    def get_private_messages(self, user1: str, user2: str, limit: int = 100) -> list:
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT
                pm.id, pm.sender_username, pm.receiver_username, pm.text, pm.timestamp, pm.reply_to_id, pm.avatar,
                r.sender_username AS reply_sender_username, r.text AS reply_text, r.avatar AS reply_avatar
            FROM private_messages pm
            LEFT JOIN private_messages r ON pm.reply_to_id = r.id
            WHERE (pm.sender_username = ? AND pm.receiver_username = ?)
               OR (pm.sender_username = ? AND pm.receiver_username = ?)
            ORDER BY pm.timestamp ASC
            LIMIT ?
        ''', (user1, user2, user2, user1, limit))
        return cursor.fetchall()

db = Database()
connected_clients: Set[websockets.WebSocketServerProtocol] = set()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username: str) -> str:
    """Создание JWT токена"""
    payload = {'username': username}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token: str) -> str:
    """Верификация JWT токена"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['username']
    except jwt.InvalidTokenError:
        return None

class HTTPHandler(BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        """Установка CORS заголовков"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    
    def handle_one_request(self):
        """Обработка одного запроса с улучшенной обработкой ошибок"""
        try:
            super().handle_one_request()
        except ConnectionAbortedError:
            print(f"Connection aborted by client: {self.client_address}")
        except Exception as e:
            print(f"Error handling request: {e}")
            try:
                if hasattr(self, 'wfile') and not self.wfile.closed:
                    self.send_error(500)
            except:
                pass  # Игнорируем ошибки при отправке ошибки
    
    def do_OPTIONS(self):
        """Обработка OPTIONS запросов для CORS"""
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
        elif self.path.startswith('/user/profile'): # Новый маршрут для получения профиля пользователя
            self.handle_get_user_profile()
        elif self.path.startswith('/users/search'): # Новый маршрут для поиска пользователей
            self.handle_search_users()
        else:
            self.send_error(404)

    def do_POST(self):
        print(f"do_POST: Path received: {self.path}")
        if self.path == '/register':
            self.handle_register()
        elif self.path == '/login':
            self.handle_login()
        elif self.path == '/message/favorite':
            self.handle_favorite_message()
        elif self.path == '/message/edit':
            self.handle_edit_message()
        elif self.path == '/user/profile': # Новый маршрут для обновления профиля
            self.handle_update_user_profile()
        else:
            self.send_error(404)

    def serve_file(self, filename: str, content_type: str):
        try:
            print(f"serve_file: Attempting to serve file: {filename} with content type: {content_type}")
            with open(filename, 'r', encoding='utf-8') as f: # Указываем кодировку UTF-8
                content = f.read().encode('utf-8') # Читаем как текст, затем кодируем в UTF-8
            
            # Проверяем, что соединение еще активно
            if hasattr(self, 'wfile') and not self.wfile.closed:
                self.send_response(200)
                self.send_header('Content-type', f'{content_type}; charset=utf-8')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                print(f"serve_file: Successfully served file: {filename}")
            else:
                print(f"serve_file: Connection closed, skipping file: {filename}")
                
        except FileNotFoundError:
            print(f"serve_file: File not found: {filename}")
            if hasattr(self, 'wfile') and not self.wfile.closed:
                self.send_error(404)
        except ConnectionAbortedError:
            print(f"serve_file: Connection aborted by client while serving: {filename}")
            # Не отправляем ошибку, так как соединение уже разорвано
        except Exception as e:
            print(f"serve_file: Error serving file {filename}: {e}")
            if hasattr(self, 'wfile') and not self.wfile.closed:
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
        avatar = data.get('avatar', None) # Получаем аватар из запроса
        about_me = data.get('aboutMe', None) # Получаем описание о себе из запроса
        
        print(f"handle_register: Received registration attempt for username: {username}")
        print(f"handle_register: Password length: {len(password) if password else 0}")
        print(f"handle_register: Avatar: {avatar}")
        print(f"handle_register: AboutMe: {about_me}")

        if not username or not password:
            print("handle_register: Missing username or password.")
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False, 
                'message': 'Заполните все поля'
            }).encode())
            return
        
        password_hash = hash_password(password)
        
        try:
            if db.add_user_with_avatar(username, password_hash, avatar, about_me):
                print(f"handle_register: User {username} registered successfully.")
                self.send_response(200)
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    'success': True,
                    'message': 'Регистрация успешна'
                }).encode())
            else:
                print(f"handle_register: User {username} already exists.")
                self.send_response(400)
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    'success': False, 
                    'message': 'Пользователь уже существует'
                }).encode())
        except Exception as e:
            print(f"handle_register: Error during user registration: {e}")
            self.send_response(500)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Внутренняя ошибка сервера при регистрации'
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
                'user': {'username': username, 'avatar': user_data[4], 'aboutMe': user_data[5]} # Возвращаем аватар и описание о себе
            }).encode())
        else:
            self.send_response(401)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False, 
                'message': 'Неверные данные для входа'
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

        if not isinstance(message_id, int) or not isinstance(is_favorite, bool):
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Некорректные данные messageId или isFavorite'}).encode())
            return

        # Проверяем, что сообщение принадлежит текущему пользователю, если это необходимо
        # (Пока пропускаем эту проверку, так как это общий чат)

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
        
        messages = db.get_messages(username=username) # Передаем username
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
                'avatar': msg[8] # Добавляем аватар
            }
            for msg in messages
        ]
        print(f"HTTPHandler.handle_get_messages: Formatted HTTP messages: {formatted_messages}") # ДОБАВЛЕНО ДЛЯ ОТЛАДКИ
        
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
                'avatar': msg[8] # Добавляем аватар
            }
            for msg in messages
        ]
        print(f"HTTPHandler.handle_get_favorite_messages: Formatted HTTP favorite messages: {formatted_messages}")
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(formatted_messages).encode())

    def handle_get_user_profile(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            token = None

        requesting_username = verify_token(token) if token else None

        if not requesting_username: # Если запрос неавторизован, все равно пытаемся отдать публичные данные
            # Если мы хотим, чтобы профили были доступны только авторизованным пользователям, здесь можно вернуть 401
            pass # Пока разрешаем просмотр всем, но это можно изменить

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
            # user_data: (id, username, password_hash, created_at, avatar, about_me)
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

        search_term = parse_qs(urlparse(self.path).query).get('username', [''])[0] # Исправлено: 'username' вместо 'term'
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
        print(f"HTTPHandler.handle_search_users: Found users: {formatted_users}")

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
        print(f"handle_edit_message: Received request from username: {username}")
        
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
        print(f"handle_edit_message: Raw POST data: {post_data}")

        try:
            data = json.loads(post_data)
            message_id = data.get('messageId')
            new_text = data.get('newText', '').strip()
            print(f"handle_edit_message: Parsed data: messageId={message_id}, newText='{new_text}'")
        except (json.JSONDecodeError, TypeError):
            print(f"handle_edit_message: Error parsing JSON data: {post_data}")
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Некорректный запрос'}).encode())
            return

        if not isinstance(message_id, int) or not isinstance(new_text, str) or not new_text:
            print(f"handle_edit_message: Invalid data types or empty new_text. messageId={message_id}, newText='{new_text}'")
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Некорректные данные messageId или newText'}).encode())
            return
        
        edited_timestamp = db.update_message_text(message_id, new_text, username)
        print(f"handle_edit_message: DB update result for message ID {message_id}: edited_timestamp={edited_timestamp}")
        
        if edited_timestamp:
            self.send_response(200)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'message': 'Сообщение обновлено', 'editedTimestamp': edited_timestamp}).encode())
        else:
            self.send_response(403) # Forbidden, если пользователь не владеет сообщением
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Невозможно обновить сообщение. Возможно, оно не ваше или не найдено.'}).encode())

    def handle_update_user_profile(self):
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
            self.wfile.write(json.dumps({'success': False, 'message': 'Неавторизованный доступ'}).encode())
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data)
            new_avatar = data.get('avatar', None)
            new_about_me = data.get('aboutMe', None)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Некорректный запрос'}).encode())
            return
        
        # Обновляем данные пользователя в базе данных
        if db.update_user_profile(username, new_avatar, new_about_me):
            self.send_response(200)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'message': 'Профиль успешно обновлен'}).encode())
        else:
            self.send_response(500)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Не удалось обновить профиль'}).encode())
    def do_POST(self):
        print(f"do_POST: Path received: {self.path}")
        if self.path == '/register':
            self.handle_register()
        elif self.path == '/login':
            self.handle_login()
        elif self.path == '/message/favorite':
            self.handle_favorite_message()
        elif self.path == '/message/edit':
            self.handle_edit_message()
        elif self.path == '/user/profile/update':  # НОВЫЙ МАРШРУТ
            self.handle_update_profile()
        else:
            self.send_error(404)

    # НОВЫЙ МЕТОД ДЛЯ ОБНОВЛЕНИЯ ПРОФИЛЯ
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
            
            print(f"handle_update_profile: Updating profile for {username}")
            print(f"handle_update_profile: Avatar: {avatar[:50] if avatar else 'None'}...")
            print(f"handle_update_profile: AboutMe: {about_me}")

        except json.JSONDecodeError:
            self.send_response(400)
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': 'Некорректный запрос'
            }).encode())
            return
        
        # Обновляем данные пользователя в базе данных
        if db.update_user_profile(username, avatar, about_me):
            # Получаем обновленные данные пользователя
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
async def websocket_handler(websocket, path):
    try:
        print(f"WebSocket connection attempt from {websocket.remote_address}, path: {path}")
        
        # Получаем токен из query параметров
        query_params = parse_qs(urlparse(path).query)
        token = query_params.get('token', [''])[0]
        
        print(f"WebSocket token received: {token[:20]}..." if token else "No token provided")
        
        username = verify_token(token)
        if not username:
            print(f"WebSocket authentication failed for token: {token[:20]}...")
            await websocket.close()
            return
        
        print(f"User {username} connected from {websocket.remote_address}")
        connected_clients.add(websocket)
        
        # Храним имя пользователя в объекте WebSocket для удобства рассылки
        websocket.username = username
        
        # Отправляем историю сообщений новому клиенту
        messages = db.get_messages(username=username, limit=50)
        for msg in messages:
            message_data = {
                'id': msg[0],
                'username': msg[1],
                'text': msg[2],
                'timestamp': msg[3],
                'replyToId': msg[4],
                'isFavorite': bool(msg[5]),
                'replyToUsername': msg[6] if msg[6] else None,
                'replyToText': msg[7] if msg[7] else None,
                'avatar': msg[8] # Добавляем аватар
            }
            print(f"WebSocket_handler: Formatted message for WebSocket history: {message_data}") # ДОБАВЛЕНО ДЛЯ ОТЛАДКИ
            try:
                await websocket.send(json.dumps(message_data))
            except:
                break
        
        async for message in websocket:
            try:
                data = json.loads(message)
                
                if data.get('type') == 'message':
                    text = data.get('text', '').strip()
                    avatar = data.get('avatar', None) # Получаем аватар из WebSocket сообщения
                    
                    if text:
                        # Сохраняем сообщение в базу
                        reply_to_id = data.get('replyToId')
                        message_id = db.add_message_with_avatar(username, text, avatar, reply_to_id) # Используем новую функцию

                        # Получаем информацию об отвеченном сообщении, если reply_to_id есть
                        reply_info = None
                        if reply_to_id:
                            cursor = db.conn.cursor()
                            cursor.execute("SELECT username, text FROM messages WHERE id = ?", (reply_to_id,))
                            reply_msg = cursor.fetchone()
                            if reply_msg:
                                reply_info = {
                                    "username": reply_msg[0],
                                    "text": reply_msg[1]
                                }

                        message_data = {
                            'id': message_id,
                            'username': username,
                            'text': text,
                            'timestamp': datetime.now().isoformat(),
                            'type': 'message',
                            'replyToId': reply_to_id,
                            'isFavorite': False, # Новое сообщение по умолчанию не избранное
                            'replyToUsername': reply_info['username'] if reply_info else None,
                            'replyToText': reply_info['text'] if reply_info else None,
                            'avatar': avatar # Добавляем аватар в данные для рассылки
                        }
                        print(f"WebSocket_handler: Formatted new message for WebSocket broadcast: {message_data}") # ДОБАВЛЕНО ДЛЯ ОТЛАДКИ
                        
                        print(f"New message from {username}: {text}")
                        
                        # Рассылка сообщения всем подключенным клиентам
                        clients_to_remove = []
                        for client in connected_clients:
                            try:
                                if client.open: # Убрано условие 'and client != websocket' для отправки сообщения также отправителю
                                    await client.send(json.dumps(message_data))
                            except:
                                clients_to_remove.append(client)
                        
                        # Удаляем отключенных клиентов
                        for client in clients_to_remove:
                            connected_clients.discard(client)
                        
                        # Отправляем подтверждение отправителю
                        await websocket.send(json.dumps({
                            'type': 'status',
                            'status': 'message_sent'
                        }))
                elif data.get('type') == 'favorite_update':
                    message_id = data.get('messageId')
                    is_favorite = data.get('isFavorite')

                    if isinstance(message_id, int) and isinstance(is_favorite, bool):
                        if db.update_message_favorite_status(message_id, is_favorite):
                            print(f"Message {message_id} favorite status updated to {is_favorite}")
                            # Рассылка обновления всем подключенным клиентам
                            clients_to_remove = []
                            for client in connected_clients:
                                try:
                                    if client.open and client != websocket:
                                        await client.send(json.dumps({
                                            'type': 'favorite_update',
                                            'messageId': message_id,
                                            'isFavorite': is_favorite
                                        }))
                                except:
                                    clients_to_remove.append(client)
                            for client in clients_to_remove:
                                connected_clients.discard(client)
                elif data.get('type') == 'message_edited': # Обработка отредактированных сообщений
                    message_id = data.get('messageId')
                    new_text = data.get('newText')
                    edited_timestamp = data.get('editedTimestamp')

                    if isinstance(message_id, int) and isinstance(new_text, str) and edited_timestamp:
                        print(f"Broadcasting message edit: ID={message_id}, New Text='{new_text}'")
                        clients_to_remove = []
                        for client in connected_clients:
                            try:
                                if client.open:
                                    await client.send(json.dumps({
                                        'type': 'message_edited',
                                        'messageId': message_id,
                                        'newText': new_text,
                                        'editedTimestamp': edited_timestamp
                                    }))
                            except:
                                clients_to_remove.append(client)
                        for client in clients_to_remove:
                            connected_clients.discard(client)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"WebSocket error: {e}")
                break
    
    except Exception as e:
        print(f"WebSocket connection error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        connected_clients.discard(websocket)
        print(f"User disconnected")

def run_http_server():
    """Запуск HTTP сервера"""
    port = int(os.environ.get("PORT", 8000))
    server = HTTPServer(('0.0.0.0', port), HTTPHandler)
    server = HTTPServer(('0.0.0.0', int(os.environ.get('PORT', 8000))), HTTPHandler)
    print("HTTP сервер запущен на http://0.0.0.0:8000")
    print("Доступно по адресу: http://ваш-ip-адрес:8000")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()

async def run_websocket_server():
    """Запуск WebSocket сервера"""
    
    try:
        port = int(os.environ.get("PORT", 9001))
        async with websockets.serve(websocket_handler, "0.0.0.0", port, max_size=None) as server:
            print("WebSocket сервер запущен на ws://0.0.0.0:9001")
            print("WebSocket сервер готов принимать соединения")
            await asyncio.Future()  # run forever
    except Exception as e:
        print(f"Ошибка запуска WebSocket сервера: {e}")
        import traceback
        traceback.print_exc()

async def main():
    """Основная функция запуска серверов"""
    # Запускаем HTTP сервер в отдельном потоке
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()
    
    # Запускаем WebSocket сервер в основном потоке
    await run_websocket_server()

if __name__ == '__main__':
    print("Запуск мессенджера...")
    print("=" * 50)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Сервер остановлен") 
