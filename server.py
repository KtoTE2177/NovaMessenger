from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# Временное хранилище
users = {"admin": "password123", "test": "test123"}
messages = []

# Главная страница - интерфейс мессенджера
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

# Раздача статических файлов (CSS, JS, иконки)
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

# API endpoints
@app.route('/api/status')
def status():
    return jsonify({"status": "online", "users": len(users), "messages": len(messages)})

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if username in users and users[username] == password:
            return jsonify({'success': True, 'username': username})
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    except:
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if username in users:
            return jsonify({'success': False, 'error': 'User exists'}), 400
        
        users[username] = password
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route('/api/messages', methods=['GET', 'POST'])
def api_messages():
    try:
        if request.method == 'GET':
            return jsonify({'success': True, 'messages': messages})
        else:
            data = request.get_json()
            message_text = data.get('message', '').strip()
            username = data.get('username', '').strip()
            
            if message_text and username:
                message_data = {
                    'username': username,
                    'message': message_text,
                    'timestamp': datetime.now().isoformat()
                }
                messages.append(message_data)
                return jsonify({'success': True})
            return jsonify({'success': False, 'error': 'Empty message'}), 400
    except:
        return jsonify({'success': False, 'error': 'Server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)


