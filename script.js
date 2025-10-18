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
}

function showLogin() {
    console.log('🔄 Showing login form');
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('loginForm').style.display = 'block';
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
    alert(message); // Простой alert вместо сложных уведомлений
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
        const messageElement = document.createElement('div');
        messageElement.className = 'message';
        messageElement.innerHTML = `
            <div class="message-header">
                <strong>${msg.username}</strong>
                <span>${new Date(msg.timestamp).toLocaleString()}</span>
            </div>
            <div class="message-text">${msg.text}</div>
        `;
        messagesDiv.appendChild(messageElement);
    });
    
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
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
            loadMessages();
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

function startMessagePolling() {
    if (messageInterval) {
        clearInterval(messageInterval);
    }
    
    messageInterval = setInterval(() => {
        const token = localStorage.getItem('token');
        if (token) {
            loadMessages();
        }
    }, 5000);
}

function updateUserInfo() {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    const userInfoElement = document.getElementById('userInfo');
    
    if (userInfoElement && user.username) {
        userInfoElement.textContent = `Logged in as: ${user.username}`;
    }
}

// =============================================
// ОБРАБОТЧИКИ СОБЫТИЙ
// =============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 NovaMessenger initialized');
    
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }
    
    checkAuthStatus();
});

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
            localStorage.removeItem('token');
            localStorage.removeItem('user');
        }
    }
    
    console.log('❌ User is not logged in');
    showAuth();
    return false;
}

// =============================================
// ЭКСПОРТ ФУНКЦИЙ В ГЛОБАЛЬНУЮ ОБЛАСТЬ
// =============================================

window.login = login;
window.register = register;
window.logout = logout;
window.showRegister = showRegister;
window.showLogin = showLogin;
window.showChat = showChat;
window.showAuth = showAuth;
window.sendMessage = sendMessage;
window.checkAuthStatus = checkAuthStatus;

console.log('✅ NovaMessenger script loaded successfully!');
