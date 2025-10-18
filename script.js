// =============================================
// NovaMessenger - Полный клиентский код
// =============================================

// Глобальные переменные
let currentUser = null;
let messageInterval = null;

// =============================================
// ФУНКЦИИ АУТЕНТИФИКАЦИИ
// =============================================

function login() {
    console.log('🔐 Attempting login...');
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
    
    if (!username || !password) {
        alert('⚠️ Please fill in all fields');
        return;
    }
    
    showLoading('Logging in...');
    
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        console.log('Login response:', data);
        
        if (data.success) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            currentUser = data.user;
            showNotification('✅ Login successful!', 'success');
            showChat();
        } else {
            showNotification('❌ ' + data.message, 'error');
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Login error:', error);
        showNotification('🔌 Network error', 'error');
    });
}

function register() {
    console.log('📝 Attempting registration...');
    const username = document.getElementById('registerUsername').value.trim();
    const password = document.getElementById('registerPassword').value.trim();
    const confirmPassword = document.getElementById('registerConfirmPassword').value.trim();
    
    if (!username || !password) {
        alert('⚠️ Please fill in all fields');
        return;
    }
    
    if (password !== confirmPassword) {
        alert('🔒 Passwords do not match');
        return;
    }
    
    if (password.length < 3) {
        alert('🔒 Password must be at least 3 characters');
        return;
    }
    
    showLoading('Creating account...');
    
    fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
            username, 
            password,
            avatar: null,
            aboutMe: null
        })
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        console.log('Register response:', data);
        
        if (data.success) {
            showNotification('✅ Registration successful! Please login.', 'success');
            showLogin();
            // Очищаем поля
            document.getElementById('registerUsername').value = '';
            document.getElementById('registerPassword').value = '';
            document.getElementById('registerConfirmPassword').value = '';
        } else {
            showNotification('❌ ' + data.message, 'error');
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Register error:', error);
        showNotification('🔌 Network error', 'error');
    });
}

function logout() {
    console.log('🚪 Logging out...');
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    currentUser = null;
    
    if (messageInterval) {
        clearInterval(messageInterval);
        messageInterval = null;
    }
    
    showNotification('👋 Logged out successfully', 'info');
    showAuth();
}

// =============================================
// ФУНКЦИИ ИНТЕРФЕЙСА
// =============================================

function showRegister() {
    console.log('🔄 Showing register form');
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'block';
    document.getElementById('authTabs').querySelectorAll('button')[0].classList.remove('active');
    document.getElementById('authTabs').querySelectorAll('button')[1].classList.add('active');
}

function showLogin() {
    console.log('🔄 Showing login form');
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('authTabs').querySelectorAll('button')[1].classList.remove('active');
    document.getElementById('authTabs').querySelectorAll('button')[0].classList.add('active');
}

function showAuth() {
    console.log('🔄 Showing auth section');
    document.getElementById('chatSection').style.display = 'none';
    document.getElementById('authSection').style.display = 'block';
    document.getElementById('userProfile').style.display = 'none';
}

function showChat() {
    console.log('💬 Showing chat section');
    document.getElementById('authSection').style.display = 'none';
    document.getElementById('chatSection').style.display = 'block';
    document.getElementById('userProfile').style.display = 'none';
    
    loadMessages();
    startMessagePolling();
    updateUserInfo();
}

function showUserProfile() {
    console.log('👤 Showing user profile');
    document.getElementById('chatSection').style.display = 'none';
    document.getElementById('userProfile').style.display = 'block';
    loadUserProfile();
}

function showLoading(message = 'Loading...') {
    const loadingEl = document.getElementById('loading');
    if (loadingEl) {
        loadingEl.textContent = message;
        loadingEl.style.display = 'block';
    }
}

function hideLoading() {
    const loadingEl = document.getElementById('loading');
    if (loadingEl) {
        loadingEl.style.display = 'none';
    }
}

function showNotification(message, type = 'info') {
    console.log(`📢 ${type}: ${message}`);
    
    // Создаем уведомление
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        background: ${type === 'error' ? '#ff4444' : type === 'success' ? '#44ff44' : '#4444ff'};
        color: white;
        border-radius: 5px;
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    // Удаляем через 3 секунды
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

// =============================================
// ФУНКЦИИ ЧАТА
// =============================================

function loadMessages() {
    const token = localStorage.getItem('token');
    
    if (!token) {
        console.log('❌ No token for loading messages');
        return;
    }
    
    fetch('/messages', {
        headers: {
            'Authorization': 'Bearer ' + token
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(messages => {
        console.log(`📨 Loaded ${messages.length} messages`);
        displayMessages(messages);
    })
    .catch(error => {
        console.error('❌ Error loading messages:', error);
        if (error.message.includes('Unauthorized')) {
            showNotification('🔒 Session expired. Please login again.', 'error');
            logout();
        }
    });
}

function displayMessages(messages) {
    const messagesDiv = document.getElementById('messages');
    if (!messagesDiv) return;
    
    messagesDiv.innerHTML = '';
    
    if (messages.length === 0) {
        messagesDiv.innerHTML = '<div class="no-messages">No messages yet. Be the first to send one!</div>';
        return;
    }
    
    messages.forEach(msg => {
        const messageElement = createMessageElement(msg);
        messagesDiv.appendChild(messageElement);
    });
    
    // Прокручиваем вниз
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function createMessageElement(msg) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message';
    messageDiv.dataset.messageId = msg.id;
    
    const timestamp = new Date(msg.timestamp).toLocaleString();
    
    let messageHTML = `
        <div class="message-header">
            <strong class="username">${escapeHtml(msg.username)}</strong>
            <span class="timestamp">${timestamp}</span>
    `;
    
    // Показываем иконку избранного
    if (msg.isFavorite) {
        messageHTML += ` <span class="favorite-icon">⭐</span>`;
    }
    
    messageHTML += `</div>`;
    messageHTML += `<div class="message-text">${escapeHtml(msg.text)}</div>`;
    
    // Если есть ответ на сообщение
    if (msg.replyToId && msg.replyToText) {
        messageHTML += `
            <div class="reply-context">
                ↪ Reply to <strong>${escapeHtml(msg.replyToUsername)}</strong>: 
                ${escapeHtml(msg.replyToText.substring(0, 50))}${msg.replyToText.length > 50 ? '...' : ''}
            </div>
        `;
    }
    
    // Кнопки действий (только для своих сообщений)
    const token = localStorage.getItem('token');
    if (token) {
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        if (user.username === msg.username) {
            messageHTML += `
                <div class="message-actions">
                    <button onclick="editMessage(${msg.id})">✏️ Edit</button>
                    <button onclick="toggleFavorite(${msg.id}, ${!msg.isFavorite})">
                        ${msg.isFavorite ? '💔 Unfavorite' : '❤️ Favorite'}
                    </button>
                </div>
            `;
        } else {
            messageHTML += `
                <div class="message-actions">
                    <button onclick="toggleFavorite(${msg.id}, ${!msg.isFavorite})">
                        ${msg.isFavorite ? '💔 Unfavorite' : '❤️ Favorite'}
                    </button>
                    <button onclick="replyToMessage(${msg.id}, '${escapeHtml(msg.username)}')">↪ Reply</button>
                </div>
            `;
        }
    }
    
    messageDiv.innerHTML = messageHTML;
    return messageDiv;
}

function sendMessage() {
    const token = localStorage.getItem('token');
    const messageInput = document.getElementById('messageInput');
    const text = messageInput.value.trim();
    
    if (!text) {
        showNotification('💬 Message cannot be empty', 'error');
        return;
    }
    
    if (!token) {
        showNotification('🔒 Please login first', 'error');
        return;
    }
    
    showLoading('Sending message...');
    
    fetch('/message/send', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ text })
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        console.log('Send message response:', data);
        
        if (data.success) {
            messageInput.value = '';
            showNotification('✅ Message sent!', 'success');
            loadMessages(); // Перезагружаем сообщения
        } else {
            showNotification('❌ ' + data.message, 'error');
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Error sending message:', error);
        showNotification('🔌 Network error', 'error');
    });
}

function toggleFavorite(messageId, isFavorite) {
    const token = localStorage.getItem('token');
    
    if (!token) {
        showNotification('🔒 Please login first', 'error');
        return;
    }
    
    fetch('/message/favorite', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ 
            messageId: parseInt(messageId),
            isFavorite: isFavorite
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(isFavorite ? '❤️ Added to favorites' : '💔 Removed from favorites', 'success');
            loadMessages(); // Обновляем сообщения
        } else {
            showNotification('❌ ' + data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error toggling favorite:', error);
        showNotification('🔌 Network error', 'error');
    });
}

function editMessage(messageId) {
    const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
    const messageText = messageElement.querySelector('.message-text').textContent;
    
    const newText = prompt('Edit your message:', messageText);
    
    if (newText !== null && newText.trim() !== '' && newText !== messageText) {
        const token = localStorage.getItem('token');
        
        fetch('/message/edit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({ 
                messageId: parseInt(messageId),
                newText: newText.trim()
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('✅ Message updated!', 'success');
                loadMessages(); // Перезагружаем сообщения
            } else {
                showNotification('❌ ' + data.message, 'error');
            }
        })
        .catch(error => {
            console.error('Error editing message:', error);
            showNotification('🔌 Network error', 'error');
        });
    }
}

function replyToMessage(messageId, username) {
    const messageInput = document.getElementById('messageInput');
    messageInput.value = `@${username} `;
    messageInput.focus();
    showNotification(`↪ Replying to ${username}`, 'info');
}

// =============================================
// ФУНКЦИИ ПОЛЬЗОВАТЕЛЯ
// =============================================

function updateUserInfo() {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    const userInfoElement = document.getElementById('userInfo');
    
    if (userInfoElement && user.username) {
        userInfoElement.textContent = `Logged in as: ${user.username}`;
    }
}

function loadUserProfile() {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    const profileElement = document.getElementById('profileContent');
    
    if (profileElement && user.username) {
        profileElement.innerHTML = `
            <h3>👤 ${escapeHtml(user.username)}</h3>
            <p><strong>Avatar:</strong> ${user.avatar || 'No avatar'}</p>
            <p><strong>About me:</strong> ${user.aboutMe || 'No description'}</p>
            <button onclick="showEditProfile()">✏️ Edit Profile</button>
            <button onclick="showChat()">💬 Back to Chat</button>
        `;
    }
}

function showEditProfile() {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    
    const newAvatar = prompt('Enter new avatar URL (optional):', user.avatar || '');
    const newAboutMe = prompt('Enter about me text (optional):', user.aboutMe || '');
    
    if (newAvatar !== null || newAboutMe !== null) {
        updateProfile(newAvatar !== null ? newAvatar : user.avatar, 
                     newAboutMe !== null ? newAboutMe : user.aboutMe);
    }
}

function updateProfile(avatar, aboutMe) {
    const token = localStorage.getItem('token');
    
    if (!token) {
        showNotification('🔒 Please login first', 'error');
        return;
    }
    
    fetch('/user/profile/update', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ 
            avatar: avatar,
            aboutMe: aboutMe
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('✅ Profile updated!', 'success');
            // Обновляем данные пользователя
            localStorage.setItem('user', JSON.stringify(data.user));
            loadUserProfile();
        } else {
            showNotification('❌ ' + data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error updating profile:', error);
        showNotification('🔌 Network error', 'error');
    });
}

// =============================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function startMessagePolling() {
    // Останавливаем предыдущий интервал если есть
    if (messageInterval) {
        clearInterval(messageInterval);
    }
    
    // Загружаем сообщения каждые 10 секунд
    messageInterval = setInterval(() => {
        const token = localStorage.getItem('token');
        if (token) {
            loadMessages();
        }
    }, 10000);
}

function checkAuthStatus() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
        try {
            currentUser = JSON.parse(user);
            console.log('✅ User is logged in:', currentUser.username);
            showChat();
            return true;
        } catch (e) {
            console.error('Error parsing user data:', e);
            localStorage.removeItem('token');
            localStorage.removeItem('user');
        }
    }
    
    console.log('❌ User is not logged in');
    showAuth();
    return false;
}

// =============================================
// ОБРАБОТЧИКИ СОБЫТИЙ
// =============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 NovaMessenger initialized');
    
    // Enter key для отправки сообщения
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }
    
    // Enter key для форм логина/регистрации
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                login();
            }
        });
    }
    
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                register();
            }
        });
    }
    
    // Проверяем статус аутентификации
    checkAuthStatus();
    
    // Добавляем CSS анимации
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        .notification {
            animation: slideIn 0.3s ease;
        }
    `;
    document.head.appendChild(style);
});

// =============================================
// ЭКСПОРТ ФУНКЦИЙ В ГЛОБАЛЬНУЮ ОБЛАСТЬ
// =============================================

// Делаем все функции глобальными для HTML onclick
window.login = login;
window.register = register;
window.logout = logout;
window.showRegister = showRegister;
window.showLogin = showLogin;
window.showChat = showChat;
window.showAuth = showAuth;
window.showUserProfile = showUserProfile;
window.sendMessage = sendMessage;
window.toggleFavorite = toggleFavorite;
window.editMessage = editMessage;
window.replyToMessage = replyToMessage;
window.showEditProfile = showEditProfile;
window.checkAuthStatus = checkAuthStatus;

console.log('✅ NovaMessenger script loaded successfully!');
console.log('📋 Available functions:', Object.keys(window).filter(key => 
    typeof window[key] === 'function' && 
    !key.startsWith('_') && 
    key !== 'console' &&
    key !== 'alert' &&
    key !== 'confirm' &&
    key !== 'prompt'
));
