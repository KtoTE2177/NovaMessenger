from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.')  # Добавьте static_folder='.'
CORS(app)  # Разрешаем запросы с фронтенда

# Временное хранилище (в продакшене используйте базу данных)
users = {
    "admin": "password123",  # Пример пользователя
    "test": "test123"
}
messages = []
active_users = set()

@app.route('/')
def home():
    return jsonify({"status": "iNOVA Messenger API is running"})

@app.route('/api/status')
def status():
    return jsonify({
        "status": "online", 
        "users_count": len(active_users),
        "messages_count": len(messages)
    })

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        logger.info(f"Login attempt: {data}")
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        # Простая проверка (в реальном приложении используйте хэширование паролей!)
        if username in users and users[username] == password:
            active_users.add(username)
            logger.info(f"User {username} logged in successfully")
            return jsonify({
                'success': True, 
                'token': f'token-{username}',  # Простой токен
                'username': username
            })
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        logger.info(f"Registration attempt: {data}")
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        if username in users:
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        
        # Сохраняем пользователя (в реальном приложении - хэшируйте пароль!)
        users[username] = password
        logger.info(f"User {username} registered successfully")
        
        return jsonify({'success': True, 'message': 'Registration successful'})
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route('/api/messages', methods=['GET', 'POST'])
def api_messages():
    try:
        if request.method == 'GET':
            # Возвращаем последние 50 сообщений
            recent_messages = messages[-50:] if len(messages) > 50 else messages
            return jsonify({
                'success': True,
                'messages': recent_messages
            })
            
        else:  # POST
            data = request.get_json()
            
            if not data:
                return jsonify({'success': False, 'error': 'No data provided'}), 400
                
            message_text = data.get('message', '').strip()
            username = data.get('username', '').strip()
            
            if not message_text or not username:
                return jsonify({'success': False, 'error': 'Message and username required'}), 400
            
            # Сохраняем сообщение
            message_data = {
                'id': len(messages) + 1,
                'username': username,
                'message': message_text,
                'timestamp': datetime.now().isoformat()
            }
            
            messages.append(message_data)
            logger.info(f"New message from {username}: {message_text}")
            
            # Ограничиваем историю сообщений (последние 1000)
            if len(messages) > 1000:
                messages.pop(0)
            
            return jsonify({'success': True, 'message': message_data})
            
    except Exception as e:
        logger.error(f"Messages error: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route('/api/users', methods=['GET'])
def api_users():
    return jsonify({
        'success': True,
        'active_users': list(active_users),
        'total_users': len(users)
    })

@app.route('/api/logout', methods=['POST'])
def api_logout():
    data = request.get_json()
    username = data.get('username', '').strip()
    
    if username in active_users:
        active_users.remove(username)
        logger.info(f"User {username} logged out")
    
    return jsonify({'success': True})
# Раздача статических файлов
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    try:
        # Разрешаем только безопасные файлы
        allowed_extensions = ['.html', '.css', '.js', '.ico', '.png', '.jpg', '.json']
        if any(filename.endswith(ext) for ext in allowed_extensions):
            return send_from_directory('.', filename)
        return "File not allowed", 404
    except Exception as e:
        return f"Error: {str(e)}", 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting iNOVA Messenger API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)


