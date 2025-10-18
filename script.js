// Конфигурация сервера - ЗАМЕНИТЕ НА ВАШ РЕАЛЬНЫЙ IP АДРЕС
const SERVER_IP = '192.168.0.118';
const API_BASE = `http://${SERVER_IP}:8000`;
// WebSocket отключен, так как приложение работает без него
const WS_URL = '';

let currentUser = null;
let isConnected = true; // Всегда подключены через REST
let emojiPickerVisible = false;
let messageCount = 0;
let contextMenuVisible = false;
let currentMessageElement = null;
let replyToMessageId = null;
let replyToUsername = null;
let replyToText = null;
let editingMessageId = null;
let isFavoritesView = false;
let currentPrivateChatUser = null;
let privateChats = {};
let currentUserStatus = 'online';
let bottomRightMenuVisible = false;

// Функция для генерации дефолтного аватара (SVG)
function generateDefaultAvatar(username) {
    if (!username) return '';
    const initial = username.charAt(0).toUpperCase();
    const color = getAvatarColor(username);
    return `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50%' cy='50%' r='50%' fill='${color}'/%3E%3Ctext x='50%' y='50%' font-family='Inter, sans-serif' font-size='45' text-anchor='middle' dominant-baseline='central' fill='white'%3E${initial}%3C/text%3E%3C/svg%3E`;
}

// Вспомогательная функция для получения цвета аватара на основе имени пользователя
function getAvatarColor(username) {
    const colors = [
        '#FF5733', '#33FF57', '#3357FF', '#FF33F6', '#F6FF33', '#33FFF6',
        '#FF8333', '#83FF33', '#8333FF', '#FF3383', '#33FF83', '#8333FF'
    ];
    let hash = 0;
    for (let i = 0; i < username.length; i++) {
        hash = username.charCodeAt(i) + ((hash << 5) - hash);
    }
    const index = Math.abs(hash % colors.length);
    return colors[index];
}

// Функция для отображения превью аватара
function displayAvatarPreview(avatarUrl) {
    const avatarPreview = document.getElementById('avatar-preview');
    const defaultAvatarPreview = document.getElementById('default-avatar-preview');
    const lobbyAvatarPreview = document.getElementById('lobby-avatar-preview');
    const lobbyDefaultAvatarPreview = document.getElementById('lobby-default-avatar-preview');

    if (avatarPreview && defaultAvatarPreview) {
        if (avatarUrl && avatarUrl.startsWith('data:image')) {
            avatarPreview.src = avatarUrl;
            avatarPreview.classList.remove('hidden');
            defaultAvatarPreview.classList.add('hidden');
        } else {
            avatarPreview.classList.add('hidden');
            defaultAvatarPreview.classList.remove('hidden');
            if (currentUser && currentUser.username) {
                defaultAvatarPreview.textContent = currentUser.username.charAt(0).toUpperCase();
                defaultAvatarPreview.style.backgroundColor = getAvatarColor(currentUser.username);
            } else {
                defaultAvatarPreview.textContent = '';
                defaultAvatarPreview.style.backgroundColor = '';
            }
        }
    }

    if (lobbyAvatarPreview && lobbyDefaultAvatarPreview) {
        if (avatarUrl && avatarUrl.startsWith('data:image')) {
            lobbyAvatarPreview.src = avatarUrl;
            lobbyAvatarPreview.classList.remove('hidden');
            lobbyDefaultAvatarPreview.classList.add('hidden');
        } else {
            lobbyAvatarPreview.classList.add('hidden');
            lobbyDefaultAvatarPreview.classList.remove('hidden');
            if (currentUser && currentUser.username) {
                lobbyDefaultAvatarPreview.textContent = currentUser.username.charAt(0).toUpperCase();
                lobbyDefaultAvatarPreview.style.backgroundColor = getAvatarColor(currentUser.username);
            } else {
                lobbyDefaultAvatarPreview.textContent = '';
                lobbyDefaultAvatarPreview.style.backgroundColor = '';
            }
        }
    }
}

async function handleAvatarChange(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            displayAvatarPreview(e.target.result);
        };
        reader.readAsDataURL(file);
    }
}

// Функция для обновления UI лобби аккаунта
function updateLobbyUI() {
    console.log('updateLobbyUI: Function called.');
    const lobbyUsernameElement = document.getElementById('lobby-username');
    const lobbyAvatarPreview = document.getElementById('lobby-avatar-preview');
    const lobbyDefaultAvatarPreview = document.getElementById('lobby-default-avatar-preview');
    const lobbyStatusIndicator = document.getElementById('lobby-status-indicator');
    const currentStatusText = document.getElementById('current-status-text');
    const statusToggleButton = document.getElementById('status-toggle-button');

    if (!lobbyUsernameElement || !lobbyAvatarPreview || !lobbyDefaultAvatarPreview || 
        !lobbyStatusIndicator || !currentStatusText || !statusToggleButton) {
        console.error('Lobby UI elements not found!');
        return;
    }

    if (currentUser) {
        lobbyUsernameElement.textContent = currentUser.username;

        // Обновляем аватар
        if (currentUser.avatar && currentUser.avatar.startsWith('data:image')) {
            lobbyAvatarPreview.src = currentUser.avatar;
            lobbyAvatarPreview.classList.remove('hidden');
            lobbyDefaultAvatarPreview.classList.add('hidden');
        } else {
            lobbyAvatarPreview.classList.add('hidden');
            lobbyDefaultAvatarPreview.classList.remove('hidden');
            if (currentUser.username) {
                lobbyDefaultAvatarPreview.textContent = currentUser.username.charAt(0).toUpperCase();
                lobbyDefaultAvatarPreview.style.backgroundColor = getAvatarColor(currentUser.username);
            }
        }

        // Обновляем статус
        lobbyStatusIndicator.className = 'status-indicator';
        lobbyStatusIndicator.classList.add(currentUserStatus);

        switch (currentUserStatus) {
            case 'online':
                currentStatusText.textContent = 'В сети';
                lobbyStatusIndicator.style.backgroundColor = 'var(--success)';
                statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--success)"></i> <span id="current-status-text">В сети</span>';
                break;
            case 'busy':
                currentStatusText.textContent = 'Занят';
                lobbyStatusIndicator.style.backgroundColor = 'var(--danger)';
                statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--danger)"></i> <span id="current-status-text">Занят</span>';
                break;
            case 'away':
                currentStatusText.textContent = 'Нет на месте';
                lobbyStatusIndicator.style.backgroundColor = 'var(--accent)';
                statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--accent)"></i> <span id="current-status-text">Нет на месте</span>';
                break;
            case 'offline':
                currentStatusText.textContent = 'Не в сети';
                lobbyStatusIndicator.style.backgroundColor = 'var(--text-secondary)';
                statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--text-secondary)"></i> <span id="current-status-text">Не в сети</span>';
                break;
        }
    } else {
        lobbyUsernameElement.textContent = 'Не в сети';
        lobbyAvatarPreview.classList.add('hidden');
        lobbyDefaultAvatarPreview.classList.remove('hidden');
        lobbyDefaultAvatarPreview.textContent = '?';
        lobbyDefaultAvatarPreview.style.backgroundColor = 'var(--text-secondary)';
        lobbyStatusIndicator.className = 'status-indicator offline';
        lobbyStatusIndicator.style.backgroundColor = 'var(--text-secondary)';
        currentStatusText.textContent = 'Не в сети';
        statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--text-secondary)"></i> <span id="current-status-text">Не в сети</span>';
    }
}
// Функция для периодического обновления сообщений
function startMessagePolling() {
    setInterval(() => {
        if (currentUser && !currentPrivateChatUser && !isFavoritesView) {
            console.log('Auto-refreshing messages...');
            loadMessages(false);
        }
    }, 5000); // Обновлять каждые 5 секунд
}
// Инициализация при загрузке страницы
function init() {
    checkAuth();
    loadTheme();
    setupEventListeners();
    setupSettingsScroll();
    if (currentUser) {
        displayAvatarPreview(currentUser.avatar);
        startMessagePolling(); // Запускаем обновление сообщений
    }
    updateLobbyUI();
    console.log('Modern Messenger initialized');
    console.log('Server URL:', API_BASE);
}
// Настройка обработчиков событий
function setupEventListeners() {
    document.getElementById('login-username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') login();
    });
    
    document.getElementById('login-password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') login();
    });
    
    document.getElementById('register-username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') register();
    });
    
    document.getElementById('register-password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') register();
    });

    document.addEventListener('click', function(event) {
        const modal = document.getElementById('settings-modal');
        if (event.target === modal) {
            hideSettings();
        }
    });

    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && emojiPickerVisible) {
            hideEmojiPicker();
        }
    });
    
    const messageInput = document.getElementById('message-input');
    if (messageInput) {
        messageInput.addEventListener('focus', function() {
            if (emojiPickerVisible) {
                hideEmojiPicker();
            }
            if (contextMenuVisible) {
                hideContextMenu();
            }
        });
    }

    document.getElementById('messages').addEventListener('contextmenu', function(event) {
        const messageElement = event.target.closest('.message');
        if (messageElement) {
            event.preventDefault();
            currentMessageElement = messageElement;
            showContextMenu(event.clientX, event.clientY, messageElement);
        }
    });

    document.getElementById('clear-reply-button').addEventListener('click', clearReplyState);

    document.getElementById('reply-preview-container').addEventListener('click', function() {
        if (replyToMessageId) {
            scrollToMessageAndHighlight(replyToMessageId);
        }
    });

    document.addEventListener('click', function(event) {
        const contextMenu = document.getElementById('context-menu');
        if (contextMenu && !contextMenu.contains(event.target) && contextMenuVisible) {
            hideContextMenu();
        }
    });

    const userSearchInput = document.getElementById('user-search-input');
    if (userSearchInput) {
        userSearchInput.addEventListener('focus', function() {
            if (contextMenuVisible) {
                hideContextMenu();
            }
        });
        
        document.addEventListener('click', function(event) {
            const searchResultsList = document.getElementById('search-results-list');
            if (searchResultsList && !searchResultsList.contains(event.target) && !userSearchInput.contains(event.target)) {
                searchResultsList.style.display = 'none';
            }
        });
    }
    
    // Добавляем обработчик для кнопки смены статуса
    const statusToggleButton = document.getElementById('status-toggle-button');
    if (statusToggleButton) {
        statusToggleButton.addEventListener('click', toggleUserStatus);
    }
}

    document.getElementById('messages').addEventListener('contextmenu', function(event) {
        const messageElement = event.target.closest('.message');
        if (messageElement) {
            event.preventDefault();
            currentMessageElement = messageElement;
            showContextMenu(event.clientX, event.clientY, messageElement);
        }
    });

    document.getElementById('clear-reply-button').addEventListener('click', clearReplyState);

    document.getElementById('reply-preview-container').addEventListener('click', function() {
        if (replyToMessageId) {
            scrollToMessageAndHighlight(replyToMessageId);
        }
    });

    document.addEventListener('click', function(event) {
        const contextMenu = document.getElementById('context-menu');
        if (contextMenu && !contextMenu.contains(event.target) && contextMenuVisible) {
            hideContextMenu();
        }
    });

    const userSearchInput = document.getElementById('user-search-input');
    if (userSearchInput) {
        userSearchInput.addEventListener('focus', function() {
            if (contextMenuVisible) {
                hideContextMenu();
            }
        });
        
        document.addEventListener('click', function(event) {
            const searchResultsList = document.getElementById('search-results-list');
            if (searchResultsList && !searchResultsList.contains(event.target) && !userSearchInput.contains(event.target)) {
                searchResultsList.style.display = 'none';
            }
        });
    }

    // УДАЛИТЬ ЭТИ СТРОКИ - они ссылаются на несуществующие элементы
    // document.getElementById('menu-trigger-button').addEventListener('click', toggleBottomRightMenu);
    
    // document.addEventListener('click', function(event) {
    //     const menu = document.getElementById('bottom-right-menu');
    //     const trigger = document.getElementById('menu-trigger-button');
    //     if (bottomRightMenuVisible && menu && trigger && !menu.contains(event.target) && !trigger.contains(event.target)) {
    //         toggleBottomRightMenu();
    //     }
    // });
    
    // Добавляем обработчик для кнопки смены статуса
    const statusToggleButton = document.getElementById('status-toggle-button');
    if (statusToggleButton) {
        statusToggleButton.addEventListener('click', toggleUserStatus);
    }
}

// Настройка горячих клавиш
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            sendMessage();
        }
        
        if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
            e.preventDefault();
            logout();
        }
        
        if ((e.ctrlKey || e.metaKey) && e.key === 't') {
            e.preventDefault();
            toggleTheme();
        }
        
        if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
            e.preventDefault();
            toggleEmojiPicker();
        }
        
        if (e.key === 'Escape') {
            const modal = document.getElementById('settings-modal');
            if (modal && modal.style.display === 'block') {
                hideSettings();
            }
            if (emojiPickerVisible) {
                hideEmojiPicker();
            }
            if (contextMenuVisible) {
                hideContextMenu();
            }
            if (editingMessageId) {
                clearEditState();
            }
            if (bottomRightMenuVisible) {
                toggleBottomRightMenu();
            }
        }
    });
}

// Проверка авторизации
function checkAuth() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    console.log('checkAuth: Token found:', !!token);
    console.log('checkAuth: User data found:', !!user);
    
    if (token && user) {
        try {
            currentUser = JSON.parse(user);
            showApp();
            // WebSocket отключен
        } catch (error) {
            console.error('Error parsing user data:', error);
            logout();
        }
    } else {
        showAuth();
    }
}

// Показать/скрыть формы
function showAuth() {
    document.getElementById('auth-container').style.display = 'flex';
    document.getElementById('app-container').style.display = 'none';
    currentUser = null;
}

function showApp() {
    console.log('showApp: Function called.');
    document.getElementById('auth-container').style.display = 'none';
    document.getElementById('app-container').style.display = 'flex';
    
    hideSettings();
    hideProfileModal();
    hideImagePreview();
    
    if (currentUser) {
        document.getElementById('current-username').textContent = currentUser.username;
        document.getElementById('favorites-username').textContent = currentUser.username;
        displayAvatarPreview(currentUser.avatar);
    }
    
    switchChat('general');
    
    setTimeout(() => {
        const messagesContainer = document.getElementById('messages');
        const messageInput = document.getElementById('message-input');
        
        if (messagesContainer) {
            messagesContainer.style.display = 'block';
        }
        if (messageInput) {
            messageInput.style.display = 'block';
        }
        
        // WebSocket отключен, загружаем сообщения через REST
        loadMessages();
    }, 100);
}

// Функция для периодического обновления сообщений
function startMessagePolling() {
    setInterval(() => {
        if (currentUser && !currentPrivateChatUser && !isFavoritesView) {
            loadMessages(false);
        }
    }, 3000); // Обновлять каждые 3 секунды
}

function showLogin() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
    document.getElementById('register-username').value = '';
    document.getElementById('register-password').value = '';
}

function showRegister() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
}

// Авторизация
async function login() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showNotification('Заполните все поля', 'error');
        return;
    }
	
    try {
        showLoading(true, 'login');
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });
	
        const data = await response.json();
        
			 if (data.success) {
				localStorage.setItem('token', data.token);
				let userData = data.user;

				console.log("Login successful. Received user data:", userData);
				
				hideSettings();
				hideProfileModal();

				if (!userData.avatar) {
					userData.avatar = generateDefaultAvatar(userData.username);
				}
				localStorage.setItem('user', JSON.stringify(userData));
				currentUser = userData;
				showNotification('Вход выполнен успешно! 🎉');
				showApp();
				
				// ЗАГРУЗИТЬ СООБЩЕНИЯ ПОСЛЕ ВХОДА
				setTimeout(() => {
					loadMessages();
				}, 500);
				
			} else {
				showNotification('Ошибка: ' + data.message, 'error');
		}
    } catch (error) {
        console.error('Login error:', error);
        showNotification('Ошибка соединения с сервером', 'error');
    } finally {
        showLoading(false, 'login');
    }
}

// Регистрация
async function register() {
    const username = document.getElementById('register-username').value.trim();
    const password = document.getElementById('register-password').value;

    if (!username || !password) {
        showNotification('Заполните все поля', 'error');
        return;
    }

    if (username.length < 3) {
        showNotification('Логин должен быть не менее 3 символов', 'error');
        return;
    }

    if (password.length < 6) {
        showNotification('Пароль должен быть не менее 6 символов', 'error');
        return;
    }

    try {
        showLoading(true, 'register');
        const defaultAvatar = generateDefaultAvatar(username);
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password, avatar: defaultAvatar, aboutMe: '' })
        });

        const data = await response.json();
        
        if (data.success) {
            showNotification('Регистрация успешна! Теперь войдите. ✅');
            showLogin();
            hideSettings();
            hideProfileModal();
        } else {
            showNotification('Ошибка: ' + data.message, 'error');
        }
    } catch (error) {
        console.error('Register error:', error);
        showNotification('Ошибка соединения с сервером', 'error');
    } finally {
        showLoading(false, 'register');
    }
}

// Показать/скрыть загрузку
function showLoading(show, type) {
    const buttons = {
        'login': document.querySelector('#login-form button'),
        'register': document.querySelector('#register-form button')
    };
    
    const button = buttons[type];
    if (!button) return;

    if (show) {
        button.disabled = true;
        button.innerHTML = '<span class="loading-dots"><span></span><span></span><span></span></span>';
    } else {
        button.disabled = false;
        if (type === 'login') {
            button.innerHTML = '<span class="button-icon"><i class="fas fa-sign-in-alt"></i></span> Войти';
        } else {
            button.innerHTML = '<span class="button-icon"><i class="fas fa-user-plus"></i></span> Зарегистрироваться';
        }
    }
}

// Выход
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    currentUser = null;
    
    if (socket) {
        socket.close();
        socket = null;
    }
    
    isConnected = false;
    messageCount = 0;
    showNotification('Вы вышли из системы');
    showAuth();
    currentUserStatus = 'offline';
    updateLobbyUI();
    }

    
    try {
        console.log('connectWebSocket: Attempting to connect to:', `${WS_URL}/?token=${encodeURIComponent(token)}`);
        socket = new WebSocket(`${WS_URL}/?token=${encodeURIComponent(token)}`);
        
        socket.onopen = function() {
            console.log('WebSocket connected successfully');
            isConnected = true;
            showNotification('Соединение установлено ✅');
            currentUserStatus = 'online';
            updateLobbyUI();
            loadMessages();
        };
        
        socket.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);
                
                if (data.type === 'message') {
                    console.log('WebSocket: Received message data', data);
                    addMessageToChat(data);
                } else if (data.type === 'private_message') {
                    console.log('WebSocket: Received private message data', data);
                    const senderOrReceiver = data.username === currentUser.username ? data.receiver : data.username;
                    if (!privateChats[senderOrReceiver]) {
                        privateChats[senderOrReceiver] = [];
                    }
                    privateChats[senderOrReceiver].push(data);
                    
                    if (currentPrivateChatUser === senderOrReceiver) {
                        addMessageToChat(data, true, true);
                    } else {
                        showNotification(`Новое личное сообщение от ${data.username}`, 'info');
                        highlightPrivateChatTab(senderOrReceiver);
                    }
                } else if (data.type === 'status') {
                    console.log('Status:', data.status);
                } else if (data.type === 'user_joined') {
                    showNotification(`${data.username} присоединился к чату`);
                } else if (data.type === 'user_left') {
                    showNotification(`${data.username} покинул чат`);
                } else if (data.type === 'favorite_update') {
                    updateMessageFavoriteStatusInDOM(data.messageId, data.isFavorite);
                } else if (data.type === 'message_edited') {
                    console.log('WebSocket: Received message edited data', data);
                    updateMessageInDOM(data.messageId, data.newText, data.editedTimestamp);
                }
            } catch (error) {
                console.error('Error parsing message:', error);
            }
        };
        
        socket.onclose = function(event) {
            console.log('WebSocket disconnected:', event.code, event.reason);
            isConnected = false;
            
            if (event.code !== 1000) {
                showNotification('Соединение прервано. Переподключение...', 'error');
                setTimeout(connectWebSocket, 3000);
            }
        };
        
        socket.onerror = function(error) {
            console.error('WebSocket error:', error);
            console.error('WebSocket URL:', `${WS_URL}/?token=${encodeURIComponent(token)}`);
            showNotification('Ошибка соединения с чатом. Проверьте, что сервер запущен на порту 9001', 'error');
        };
    } catch (error) {
        console.error('WebSocket connection error:', error);
        showNotification('Не удалось установить соединение с чатом', 'error');
        setTimeout(connectWebSocket, 3000);
    }
}

// Отправка сообщения
// Отправка сообщения
async function sendMessage() {
    const input = document.getElementById('message-input');
    const text = input.value.trim();
    console.log(`sendMessage: Called. Current text: '${text}', editingMessageId: ${editingMessageId}`);
    
    if (!text) {
        showNotification('Введите сообщение', 'error');
        if (input) input.focus();
        console.log('sendMessage: Text is empty, returning early.');
        return;
    }
    
    if (editingMessageId) {
        console.log(`sendMessage: Editing mode active. Calling sendEditMessage for ID ${editingMessageId}.`);
        sendEditMessage(editingMessageId, text);
        clearEditState();
        return;
    }

    const currentReplyToMessageId = replyToMessageId;
    const currentReplyToUsername = replyToUsername;
    const currentReplyToText = replyToText;

    if (input) input.value = '';
    
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            showNotification('Ошибка авторизации', 'error');
            return;
        }

        let messageData = {
            text: text,
            replyToId: currentReplyToMessageId
        };

        // Для приватных сообщений
        if (currentPrivateChatUser) {
            messageData.receiver = currentPrivateChatUser;
        }

        const endpoint = currentPrivateChatUser ? '/private-message' : '/messages';
        
        const response = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(messageData)
        });

        const data = await response.json();
        
        if (data.success) {
            showNotification('Сообщение отправлено ✅');
            // Перезагружаем сообщения чтобы увидеть новое
            setTimeout(() => {
                if (currentPrivateChatUser) {
                    loadPrivateChatMessages(currentPrivateChatUser);
                } else {
                    loadMessages();
                }
            }, 500);
        } else {
            showNotification('Ошибка отправки сообщения: ' + data.message, 'error');
        }
        
        clearReplyState();
        
    } catch (error) {
        console.error('Error sending message:', error);
        showNotification('Ошибка отправки сообщения', 'error');
    }
}

// Отправка отредактированного сообщения
async function sendEditMessage(messageId, newText) {
    console.log(`sendEditMessage: Attempting to edit message ID ${messageId} with text: ${newText}`);
    const token = localStorage.getItem('token');
    if (!token) {
        showNotification('Вы не авторизованы', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/message/edit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ messageId: parseInt(messageId), newText })
        });

        const data = await response.json();
        console.log(`sendEditMessage: Server response for edit message ID ${messageId}:`, data);
        if (data.success) {
            showNotification('Сообщение изменено ✅');
            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({
                    type: 'message_edited',
                    messageId: messageId,
                    newText: newText,
                    editedTimestamp: data.editedTimestamp
                }));
            }
            updateMessageInDOM(messageId, newText, data.editedTimestamp);
        } else {
            showNotification('Ошибка: ' + data.message, 'error');
        }
    } catch (error) {
        console.error('Error editing message:', error);
        showNotification('Ошибка при изменении сообщения', 'error');
    }
}

// Обновление сообщения в DOM
function updateMessageInDOM(messageId, newText, editedTimestamp) {
    console.log(`updateMessageInDOM: Updating message ID ${messageId} with new text: ${newText} and timestamp: ${editedTimestamp}`);
    const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
    if (messageElement) {
        messageElement.querySelector('.main-message-text').textContent = newText;
        if (editedTimestamp) {
            const time = new Date(editedTimestamp).toLocaleTimeString('ru-RU', {
                hour: '2-digit',
                minute: '2-digit'
            });
            messageElement.querySelector('small').textContent = `${time} (изм.)`;
        }
    } else {
        console.warn(`updateMessageInDOM: Message element with ID ${messageId} not found in DOM.`);
    }
}

// Обработка нажатия Enter
function handleKeyPress(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendMessage();
    }
}

async function loadMessages(onlyFavorites = false) {
    console.log('=== loadMessages START ===');
    console.log('onlyFavorites:', onlyFavorites);
    console.log('currentUser:', currentUser);
    console.log('currentPrivateChatUser:', currentPrivateChatUser);
    
    try {
        const messagesContainer = document.getElementById('messages');
        console.log('messagesContainer:', messagesContainer);
        
        if (!messagesContainer) {
            console.error('messagesContainer not found!');
            return;
        }

        const token = localStorage.getItem('token');
        console.log('token exists:', !!token);
        
        if (!token) {
            console.error('No token found!');
            logout();
            return;
        }

        let messages = [];
        let chatTypeForDisplay = 'general';

        if (currentPrivateChatUser) {
            console.log('Loading private messages for:', currentPrivateChatUser);
            chatTypeForDisplay = 'private';
            if (privateChats[currentPrivateChatUser]) {
                messages = privateChats[currentPrivateChatUser];
                console.log(`loadMessages: Loaded private messages for ${currentPrivateChatUser} from cache:`, messages);
            } else {
                const url = `${API_BASE}/private-messages?username=${encodeURIComponent(currentPrivateChatUser)}`;
                const response = await fetch(url, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (!response.ok) {
                    throw new Error(`Ошибка загрузки личных сообщений: ${response.status}`);
                }
                messages = await response.json();
                privateChats[currentPrivateChatUser] = messages;
                console.log(`loadMessages: Loaded private messages for ${currentPrivateChatUser} from server:`, messages);
            }
        } else if (onlyFavorites) {
            chatTypeForDisplay = 'favorites';
            console.log('Loading favorite messages');
            const url = `${API_BASE}/messages/favorites`;
            const response = await fetch(url, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (response.status === 401) {
                logout();
                return;
            }
            if (!response.ok) {
                throw new Error('HTTP error ' + response.status);
            }
            messages = await response.json();
            console.log('loadMessages: Received favorite messages from server:', messages);
         } else {
            chatTypeForDisplay = 'general';
            const url = `${API_BASE}/messages`;
            console.log('Loading general messages from URL:', url);
            
            const response = await fetch(url, {
                headers: { 
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            console.log('Response status:', response.status);
            console.log('Response ok:', response.ok);
            
            if (response.status === 401) {
                console.error('Unauthorized - logging out');
                logout();
                return;
            }
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('HTTP error:', response.status, errorText);
                throw new Error(`HTTP error ${response.status}: ${errorText}`);
            }
            
            messages = await response.json();
            console.log('Received messages:', messages);
            console.log('Number of messages:', messages.length);
        }

        messagesContainer.innerHTML = '';
        messageCount = messages.length;

        if (messages.length === 0) {
            console.log('No messages, showing welcome message');
            messagesContainer.innerHTML = `
                <div class="welcome-message">
                    <div class="welcome-icon">👋</div>
                    <h3>Добро пожаловать в ${chatTypeForDisplay === 'general' ? 'общий чат!' : (chatTypeForDisplay === 'favorites' ? 'избранные сообщения!' : `чат с ${currentPrivateChatUser}!`)}</h3>
                    <p>${chatTypeForDisplay === 'general' ? 'Начните общение, отправив первое сообщение' : (chatTypeForDisplay === 'favorites' ? 'Здесь будут отображаться ваши избранные сообщения.' : `Начните личное общение с ${currentPrivateChatUser}`)}</p>
                </div>
            `;
        } else {
            console.log('Adding messages to chat...');
            messages.forEach((message, index) => {
                console.log(`Message ${index}:`, message);
                addMessageToChat(message, false, currentPrivateChatUser ? true : false);
            });
            scrollToBottom();
        }
        
        console.log('=== loadMessages END ===');
    } catch (error) {
        console.error('Ошибка загрузки сообщений:', error);
        showNotification('Ошибка загрузки сообщений: ' + error.message, 'error');
    }
}
// Обновленная функция добавления сообщения в чат
function addMessageToChat(message, animate = true, isPrivateChat = false) {
    console.log('addMessageToChat:', message, 'isPrivate:', isPrivateChat);
    
    const messagesContainer = document.getElementById('messages');
    if (!messagesContainer) return;

    // Проверяем, нужно ли отображать это сообщение в текущем чате
    if (isPrivateChat && currentPrivateChatUser) {
        const isRelevant = (message.username === currentPrivateChatUser && message.receiver === currentUser.username) ||
                          (message.username === currentUser.username && message.receiver === currentPrivateChatUser);
        
        if (!isRelevant) {
            console.log('Message not relevant for current private chat');
            return;
        }
    } else if (!isPrivateChat && currentPrivateChatUser) {
        // В приватном чате не показываем общие сообщения
        return;
    }

    const welcomeMessage = document.querySelector('.welcome-message');
    if (welcomeMessage) {
        welcomeMessage.remove();
    }

    const messageElement = document.createElement('div');
    const isOwnMessage = currentUser && message.username === currentUser.username;

    messageElement.className = `message ${isOwnMessage ? 'own' : 'other'} ${message.isTemp ? 'temp' : ''}`;
    messageElement.dataset.messageId = message.id;
    messageElement.dataset.username = message.username;
    messageElement.dataset.isFavorite = message.isFavorite || false;
    messageElement.dataset.timestamp = message.timestamp;

    const time = new Date(message.timestamp).toLocaleTimeString('ru-RU', {
        hour: '2-digit',
        minute: '2-digit'
    });

    const senderAvatar = message.avatar || generateDefaultAvatar(message.username);

    let replyPreviewHtml = '';
    if (message.replyToId && message.replyToUsername && message.replyToText) {
        replyPreviewHtml = `
            <div class="message-reply-preview" onclick="event.stopPropagation(); scrollToMessageAndHighlight('${message.replyToId}');">
                <span class="reply-label">Ответ на:</span>
                <strong>${message.replyToUsername}</strong>
                <p>${message.replyToText}</p>
            </div>
        `;
    }

    messageElement.innerHTML = `
        <div class="message-avatar-container" onclick="showProfileModal('${message.username}')">
            ${message.avatar ? 
                `<img src="${senderAvatar}" alt="Аватар ${message.username}" class="message-avatar">` : 
                `<div class="default-avatar-preview message-avatar" style="background-color: ${getAvatarColor(message.username)};">${message.username.charAt(0).toUpperCase()}</div>`
            }
        </div>
        <div class="message-content-wrapper">
            ${replyPreviewHtml}
            <strong>
                ${message.username}${isOwnMessage ? ' (Вы)' : ''}
                <span class="message-favorite-icon ${message.isFavorite ? 'active' : ''}" onclick="event.stopPropagation(); toggleFavorite('${message.id}')">
                    <i class="fas fa-star"></i>
                </span>
            </strong>
            <p class="main-message-text">${message.text}</p>
            <small>${time} ${message.editedTimestamp ? `(изм. ${new Date(message.editedTimestamp).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })})` : ''} ${message.isTemp ? '⏳' : ''}</small>
        </div>
    `;

    if (animate) {
        messageElement.style.opacity = '0';
        messagesContainer.appendChild(messageElement);
        
        setTimeout(() => {
            messageElement.style.opacity = '1';
            messageElement.style.transform = 'translateY(0)';
        }, 10);
        
        messageCount++;
    } else {
        messagesContainer.appendChild(messageElement);
    }
    
    scrollToBottom();
}

// Функция для ответа на сообщение
function replyToMessage(messageElement) {
    if (!messageElement) return;

    replyToMessageId = messageElement.dataset.messageId;
    replyToUsername = messageElement.dataset.username;
    replyToText = messageElement.querySelector('.main-message-text').textContent;

    const replyPreviewContainer = document.getElementById('reply-preview-container');
    const replyUsernameElement = document.getElementById('reply-username');
    const replyTextElement = document.getElementById('reply-text');

    if (replyPreviewContainer && replyUsernameElement && replyTextElement) {
        replyUsernameElement.textContent = replyToUsername;
        replyTextElement.textContent = replyToText;
        replyPreviewContainer.classList.remove('hidden');
        document.getElementById('message-input').focus();
    }
    console.log(`Replying to: ${replyToUsername} - ${replyToText}`);
}

// Функция для очистки состояния ответа
function clearReplyState() {
    replyToMessageId = null;
    replyToUsername = null;
    replyToText = null;
    const replyPreviewContainer = document.getElementById('reply-preview-container');
    if (replyPreviewContainer) {
        replyPreviewContainer.classList.add('hidden');
    }
    const messageInput = document.getElementById('message-input');
    if (messageInput) {
        messageInput.placeholder = 'Напишите сообщение...';
    }
    console.log('Reply state cleared.');
}

// Прокрутка к последнему сообщению
function scrollToBottom() {
    const messagesContainer = document.getElementById('messages');
    if (messagesContainer) {
        messagesContainer.scrollTo({
            top: messagesContainer.scrollHeight,
            behavior: 'smooth'
        });
    }
}

// Настройки темы
function loadTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.body.className = `${savedTheme}-theme`;
    const themeSelect = document.getElementById('theme-select');
    const themeToggleIcon = document.querySelector('#theme-toggle .theme-icon');
    
    if (themeSelect) themeSelect.value = savedTheme;
    if (themeToggleIcon) {
        if (savedTheme === 'light') {
            themeToggleIcon.classList.remove('fa-sun');
            themeToggleIcon.classList.add('fa-moon');
        } else {
            themeToggleIcon.classList.remove('fa-moon');
            themeToggleIcon.classList.add('fa-sun');
        }
    }
}

function toggleTheme() {
    const currentTheme = document.body.className.includes('light') ? 'light' : 'dark';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    changeTheme(newTheme);
    showNotification(`Тема изменена на ${newTheme === 'light' ? 'светлую' : 'тёмную'}`, 'success');
    // УДАЛИТЬ эту строку - меню больше не существует
    if (bottomRightMenuVisible) {
        toggleBottomRightMenu();
    }
}

function changeTheme(theme = null) {
    const selectedTheme = theme || document.getElementById('theme-select').value;
    document.body.className = `${selectedTheme}-theme`;
    localStorage.setItem('theme', selectedTheme);
    
    const themeSelect = document.getElementById('theme-select');
    const themeToggleIcon = document.querySelector('#theme-toggle .theme-icon');
    
    if (themeSelect) themeSelect.value = selectedTheme;
    if (themeToggleIcon) {
        if (selectedTheme === 'light') {
            themeToggleIcon.classList.remove('fa-sun');
            themeToggleIcon.classList.add('fa-moon');
        } else {
            themeToggleIcon.classList.remove('fa-moon');
            themeToggleIcon.classList.add('fa-sun');
        }
    }
}

// Улучшенная функция показа настроек
function showSettings() {
    const modal = document.getElementById('settings-modal');
    if (modal) {
        if (bottomRightMenuVisible) {
            toggleBottomRightMenu();
        }
        modal.classList.add('modal-active');
        document.body.style.overflow = 'hidden';
        showSettingsTab('messenger');
        loadProfileData();
        
        // Автоматически прокручиваем к началу при открытии
        setTimeout(() => {
            const scrollArea = modal.querySelector('.modal-body-scroll-area');
            if (scrollArea) {
                scrollArea.scrollTop = 0;
            }
        }, 100);
    }
}

// Улучшенная функция переключения вкладок
function showSettingsTab(tabName) {
    console.log('Show settings tab:', tabName);
    
    // Обновляем активные кнопки вкладок
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });
    
    // Обновляем активное содержимое вкладок
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Активируем выбранную вкладку
    const activeTabButton = Array.from(document.querySelectorAll('.tab-button'))
        .find(button => button.textContent.includes(tabName === 'messenger' ? 'Мессенджер' : 'Профиль'));
    
    if (activeTabButton) {
        activeTabButton.classList.add('active');
    }
    
    const activeTabContent = document.getElementById(`${tabName}-tab-content`);
    if (activeTabContent) {
        activeTabContent.classList.add('active');
    }
    
    // Прокручиваем к началу при переключении вкладок
    const scrollArea = document.querySelector('#settings-modal .modal-body-scroll-area');
    if (scrollArea) {
        scrollArea.scrollTop = 0;
    }
}

function hideSettings() {
    const modal = document.getElementById('settings-modal');
    if (modal) {
        modal.classList.remove('modal-active');
        document.body.style.overflow = '';
    }
}

// Функция для показа уведомлений
function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    const notificationText = document.getElementById('notification-text');
    
    if (!notification || !notificationText) {
        console.log('Notification:', message);
        return;
    }
    
    notificationText.textContent = message;
    notification.className = `notification ${type}`;
    
    if (type === 'error') {
        notification.style.background = 'var(--danger)';
    } else if (type === 'warning') {
        notification.style.background = 'var(--accent)';
    } else if (type === 'info') {
        notification.style.background = 'var(--text-secondary)';
    } else {
        notification.style.background = 'var(--success)';
    }
    
    setTimeout(() => {
        notification.className = 'notification hidden';
    }, 3000);
}

// Функции для работы с эмодзи
function toggleEmojiPicker() {
    const emojiPicker = document.getElementById('emoji-picker');
    const emojiButton = document.querySelector('.emoji-button');
    console.log('toggleEmojiPicker called');
    
    if (emojiPickerVisible) {
        hideEmojiPicker();
    } else {
        showEmojiPicker();
        if (emojiButton) emojiButton.classList.add('active');
    }
}

function showEmojiPicker() {
    const emojiPicker = document.getElementById('emoji-picker');
    if (!emojiPicker) {
        console.error('Emoji picker element not found!');
        return;
    }
    console.log('showEmojiPicker called');
    
    emojiPicker.classList.remove('hidden');
    emojiPickerVisible = true;
    
    if (document.getElementById('emoji-grid').children.length === 0) {
        populateEmojiGrid();
    }
    
    setTimeout(() => {
        document.addEventListener('click', handleClickOutsideEmojiPicker);
    }, 100);
}

function hideEmojiPicker() {
    const emojiPicker = document.getElementById('emoji-picker');
    const emojiButton = document.querySelector('.emoji-button');
    
    if (emojiPicker) emojiPicker.classList.add('hidden');
    emojiPickerVisible = false;
    if (emojiButton) emojiButton.classList.remove('active');
    
    document.removeEventListener('click', handleClickOutsideEmojiPicker);
}

function handleClickOutsideEmojiPicker(event) {
    const emojiPicker = document.getElementById('emoji-picker');
    const emojiButton = document.querySelector('.emoji-button');
    
    if (emojiPicker && emojiButton) {
        if (!emojiPicker.contains(event.target) && !emojiButton.contains(event.target)) {
            hideEmojiPicker();
        }
    }
}

// Добавьте эту функцию для индикатора прокрутки
function setupSettingsScroll() {
    const scrollArea = document.querySelector('#settings-modal .modal-body-scroll-area');
    if (scrollArea) {
        scrollArea.addEventListener('scroll', function() {
            if (this.scrollTop > 10) {
                this.classList.add('scrolled');
            } else {
                this.classList.remove('scrolled');
            }
        });
    }
}
// Функция для заполнения сетки эмодзи
function populateEmojiGrid() {
    console.log('populateEmojiGrid called');
    const emojis = [
        '😃', '😄', '😁', '😆', '😅', '🤣', '☺️', '😊', '🙂', '🙃', '😉', '😌', '🥰', '😘', 
        '😙', '😋', '😛', '🤓', '😎', '🥳', '😏', '😕', '🙁', '😣', '😖', '😩', '😫', '😭', 
        '😤', '😠', '😡', '🤬', '🤯', '🥶', '🥵', '😳', '😱', '😨', '😰', '🤔', '😐', '😑', 
        '👐', '🙌', '👏', '👍', '👎', '👈', '👉', '👆', '👇', '☝️', '🗣️', '👤', '👥', '💍', 
        '👑', '🌈', '☀️', '🌤️', '☁️', '🌦️', '🌧️', '⛈️', '🌩️', '🌨️', '❄️', '☃️', '⛄', '💧', 
        '💦', '☔', '🌊', '🌫️'
    ];
    
    const emojiGrid = document.getElementById('emoji-grid');
    if (!emojiGrid) return;
    
    emojiGrid.innerHTML = '';
    
    emojis.forEach(emoji => {
        const emojiElement = document.createElement('div');
        emojiElement.className = 'emoji-item';
        emojiElement.textContent = emoji;
        emojiElement.title = emoji;
        emojiElement.onclick = () => insertEmoji(emoji);
        
        emojiGrid.appendChild(emojiElement);
    });
}

// Функция для вставки эмодзи в поле ввода
function insertEmoji(emoji) {
    const messageInput = document.getElementById('message-input');
    if (!messageInput) return;
    
    const startPos = messageInput.selectionStart;
    const endPos = messageInput.selectionEnd;
    
    messageInput.value = messageInput.value.substring(0, startPos) + 
                         emoji + 
                         messageInput.value.substring(endPos);
    
    messageInput.selectionStart = startPos + emoji.length;
    messageInput.selectionEnd = startPos + emoji.length;
    
    messageInput.focus();
    
    hideEmojiPicker();
    
    const emojiButton = document.querySelector('.emoji-button');
    if (emojiButton) {
        emojiButton.style.transform = 'scale(1.2)';
        setTimeout(() => {
            emojiButton.style.transform = 'scale(1)';
        }, 200);
    }
}
// Функция для тестирования загрузки сообщений
function testLoadMessages() {
    console.log('=== ТЕСТ ЗАГРУЗКИ СООБЩЕНИЙ ===');
    console.log('currentUser:', currentUser);
    console.log('token:', localStorage.getItem('token'));
    console.log('API_BASE:', API_BASE);
    
    loadMessages();
}

// Функция для проверки всех пользователей
async function testAllUsers() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${API_BASE}/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (response.ok) {
            const users = await response.json();
            console.log('Все пользователи:', users);
            showNotification(`Найдено пользователей: ${users.length}`);
        } else {
            console.error('Ошибка загрузки пользователей:', response.status);
        }
    } catch (error) {
        console.error('Ошибка:', error);
    }
}
// Проверка соединения (упрощенная версия)
function checkConnection() {
    // Всегда подключены через REST
    if (!currentUser) {
        showNotification('Нет авторизации', 'error');
    }
}

// Периодическая проверка соединения
setInterval(checkConnection, 10000);


// Функция для обновления UI лобби аккаунта
function updateLobbyUI() {
    console.log('updateLobbyUI: Function called.');
    const lobbyUsernameElement = document.getElementById('lobby-username');
    const lobbyAvatarPreview = document.getElementById('lobby-avatar-preview');
    const lobbyDefaultAvatarPreview = document.getElementById('lobby-default-avatar-preview');
    const lobbyStatusIndicator = document.getElementById('lobby-status-indicator');
    const currentStatusText = document.getElementById('current-status-text');
    const statusToggleButton = document.getElementById('status-toggle-button');

    if (!lobbyUsernameElement || !lobbyAvatarPreview || !lobbyDefaultAvatarPreview || 
        !lobbyStatusIndicator || !currentStatusText || !statusToggleButton) {
        console.error('Lobby UI elements not found!');
        return;
    }

    if (currentUser) {
        lobbyUsernameElement.textContent = currentUser.username;

        // Обновляем аватар
        if (currentUser.avatar && currentUser.avatar.startsWith('data:image')) {
            lobbyAvatarPreview.src = currentUser.avatar;
            lobbyAvatarPreview.classList.remove('hidden');
            lobbyDefaultAvatarPreview.classList.add('hidden');
        } else {
            lobbyAvatarPreview.classList.add('hidden');
            lobbyDefaultAvatarPreview.classList.remove('hidden');
            if (currentUser.username) {
                lobbyDefaultAvatarPreview.textContent = currentUser.username.charAt(0).toUpperCase();
                lobbyDefaultAvatarPreview.style.backgroundColor = getAvatarColor(currentUser.username);
            }
        }

        // Обновляем статус
        lobbyStatusIndicator.className = 'status-indicator';
        lobbyStatusIndicator.classList.add(currentUserStatus);

        switch (currentUserStatus) {
            case 'online':
                currentStatusText.textContent = 'В сети';
                lobbyStatusIndicator.style.backgroundColor = 'var(--success)';
                statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--success)"></i> <span id="current-status-text">В сети</span>';
                break;
            case 'busy':
                currentStatusText.textContent = 'Занят';
                lobbyStatusIndicator.style.backgroundColor = 'var(--danger)';
                statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--danger)"></i> <span id="current-status-text">Занят</span>';
                break;
            case 'away':
                currentStatusText.textContent = 'Нет на месте';
                lobbyStatusIndicator.style.backgroundColor = 'var(--accent)';
                statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--accent)"></i> <span id="current-status-text">Нет на месте</span>';
                break;
            case 'offline':
                currentStatusText.textContent = 'Не в сети';
                lobbyStatusIndicator.style.backgroundColor = 'var(--text-secondary)';
                statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--text-secondary)"></i> <span id="current-status-text">Не в сети</span>';
                break;
        }
    } else {
        lobbyUsernameElement.textContent = 'Не в сети';
        lobbyAvatarPreview.classList.add('hidden');
        lobbyDefaultAvatarPreview.classList.remove('hidden');
        lobbyDefaultAvatarPreview.textContent = '?';
        lobbyDefaultAvatarPreview.style.backgroundColor = 'var(--text-secondary)';
        lobbyStatusIndicator.className = 'status-indicator offline';
        lobbyStatusIndicator.style.backgroundColor = 'var(--text-secondary)';
        currentStatusText.textContent = 'Не в сети';
        statusToggleButton.innerHTML = '<i class="fas fa-circle" style="color: var(--text-secondary)"></i> <span id="current-status-text">Не в сети</span>';
    }
}

// Добавляем функцию для смены статуса
function toggleUserStatus() {
    const statuses = ['online', 'busy', 'away', 'offline'];
    const currentIndex = statuses.indexOf(currentUserStatus);
    const nextIndex = (currentIndex + 1) % statuses.length;
    currentUserStatus = statuses[nextIndex];
    
    updateLobbyUI();
    showNotification(`Статус изменен на: ${getStatusText(currentUserStatus)}`);
    
    // Если меню открыто, обновляем его
    if (bottomRightMenuVisible) {
        updateLobbyUI();
    }
}

function getStatusText(status) {
    const statusTexts = {
        'online': 'В сети',
        'busy': 'Занят',
        'away': 'Нет на месте',
        'offline': 'Не в сети'
    };
    return statusTexts[status] || 'Неизвестно';
}

// Инициализация при загрузке
window.onload = function() {
    init();
    setupKeyboardShortcuts();
};

// НОВЫЕ ИСПРАВЛЕННЫЕ ФУНКЦИИ:

function hideProfileModal() {
    const modal = document.getElementById('profile-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function showProfileModal(username) {
    const modal = document.getElementById('profile-modal');
    if (modal) {
        modal.style.display = 'block';
        loadProfileModalData(username);
    }
}

function loadProfileModalData(username) {
    const usernameElement = document.getElementById('profile-modal-username');
    if (usernameElement) {
        usernameElement.textContent = `Профиль ${username}`;
    }
}

function showImagePreview(src) {
    const modal = document.getElementById('image-preview-modal');
    const img = document.getElementById('image-preview-src');
    if (modal && img) {
        img.src = src;
        modal.style.display = 'block';
    }
}

function hideImagePreview() {
    const modal = document.getElementById('image-preview-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Поиск пользователей
async function searchUsers() {
    const searchInput = document.getElementById('user-search-input');
    const searchResultsList = document.getElementById('search-results-list');
    
    if (!searchInput || !searchResultsList) return;
    
    const query = searchInput.value.trim();
    
    if (query.length < 2) {
        searchResultsList.style.display = 'none';
        searchResultsList.innerHTML = '';
        return;
    }
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${API_BASE}/users/search?q=${encodeURIComponent(query)}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Ошибка поиска');
        }
        
        const users = await response.json();
        displaySearchResults(users);
        
    } catch (error) {
        console.error('Search error:', error);
        showNotification('Ошибка поиска пользователей', 'error');
    }
}
// Отображение результатов поиска
function displaySearchResults(users) {
    const searchResultsList = document.getElementById('search-results-list');
    if (!searchResultsList) return;
    
    searchResultsList.innerHTML = '';
    
    if (users.length === 0) {
        const noResultsItem = document.createElement('li');
        noResultsItem.className = 'search-result-item no-results';
        noResultsItem.textContent = 'Пользователи не найдены';
        searchResultsList.appendChild(noResultsItem);
    } else {
        users.forEach(user => {
            if (user.username === currentUser.username) return; // Пропускаем текущего пользователя
            
            const userItem = document.createElement('li');
            userItem.className = 'search-result-item';
            userItem.innerHTML = `
                <div class="user-avatar-small" style="background-color: ${getAvatarColor(user.username)}">
                    ${user.avatar ? 
                        `<img src="${user.avatar}" alt="${user.username}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">` : 
                        user.username.charAt(0).toUpperCase()
                    }
                </div>
                <span class="user-search-name">${user.username}</span>
                ${user.aboutMe ? `<span class="user-about-preview">${user.aboutMe}</span>` : ''}
            `;
            
            userItem.addEventListener('click', () => startPrivateChat(user.username));
            searchResultsList.appendChild(userItem);
        });
    }
    
    searchResultsList.style.display = 'block';
}
// Запуск приватного чата
function startPrivateChat(username) {
    console.log('Starting private chat with:', username);
    
    // Скрываем результаты поиска
    const searchResultsList = document.getElementById('search-results-list');
    const searchInput = document.getElementById('user-search-input');
    
    if (searchResultsList) searchResultsList.style.display = 'none';
    if (searchInput) searchInput.value = '';
    
    // Создаем или активируем вкладку приватного чата
    let chatTab = document.querySelector(`[data-private-chat="${username}"]`);
    
    if (!chatTab) {
        // Создаем новую вкладку
        const chatList = document.querySelector('.chat-list');
        chatTab = document.createElement('li');
        chatTab.className = 'chat-list-item private-chat-item';
        chatTab.dataset.privateChat = username;
        chatTab.innerHTML = `
            <i class="fas fa-user"></i> ${username}
            <button class="close-private-chat" onclick="closePrivateChat('${username}')">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        chatTab.addEventListener('click', (e) => {
            if (!e.target.closest('.close-private-chat')) {
                switchToPrivateChat(username);
            }
        });
        
        // Вставляем после избранного, перед общим чатом
        const favoritesTab = document.getElementById('favorites-chat-tab');
        if (favoritesTab) {
            favoritesTab.parentNode.insertBefore(chatTab, favoritesTab.nextSibling);
        } else {
            chatList.appendChild(chatTab);
        }
        
        // Инициализируем хранилище для приватного чата
        if (!privateChats[username]) {
            privateChats[username] = [];
        }
    }
    
    // Переключаемся на приватный чат
    switchToPrivateChat(username);
}
// Переключение на приватный чат
function switchToPrivateChat(username) {
    console.log('Switching to private chat with:', username);
    
    // Обновляем активные вкладки
    document.querySelectorAll('.chat-list-item').forEach(item => {
        item.classList.remove('active');
    });
    
    const chatTab = document.querySelector(`[data-private-chat="${username}"]`);
    if (chatTab) {
        chatTab.classList.add('active');
    }
    
    // Обновляем заголовок
    document.getElementById('current-chat-title').textContent = `Чат с ${username}`;
    
    // Устанавливаем текущий приватный чат
    currentPrivateChatUser = username;
    isFavoritesView = false;
    
    // Загружаем сообщения
    loadPrivateChatMessages(username);
    
    // Скрываем поле ввода для избранного, если оно было скрыто
    const messageInputContainer = document.querySelector('.message-input');
    if (messageInputContainer) {
        messageInputContainer.classList.remove('favorites-collapsed');
    }
}
// Загрузка сообщений приватного чата
async function loadPrivateChatMessages(username) {
    console.log('Loading private chat messages for:', username);
    
    const messagesContainer = document.getElementById('messages');
    if (!messagesContainer) return;
    
    messagesContainer.innerHTML = '';
    
    try {
        const token = localStorage.getItem('token');
        const url = `${API_BASE}/private-messages?username=${encodeURIComponent(username)}`;
        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) {
            throw new Error(`Ошибка загрузки сообщений: ${response.status}`);
        }
        
        const messages = await response.json();
        privateChats[username] = messages;
        
        if (messages.length === 0) {
            messagesContainer.innerHTML = `
                <div class="welcome-message">
                    <div class="welcome-icon">👋</div>
                    <h3>Начните общение с ${username}</h3>
                    <p>Отправьте первое сообщение, чтобы начать диалог</p>
                </div>
            `;
        } else {
            messages.forEach(message => {
                addMessageToChat(message, false, true);
            });
            scrollToBottom();
        }
        
    } catch (error) {
        console.error('Error loading private messages:', error);
        showNotification('Ошибка загрузки сообщений', 'error');
        
        messagesContainer.innerHTML = `
            <div class="welcome-message">
                <div class="welcome-icon">⚠️</div>
                <h3>Не удалось загрузить сообщения</h3>
                <p>Попробуйте обновить страницу</p>
            </div>
        `;
    }
}
// Закрытие приватного чата
function closePrivateChat(username) {
    console.log('Closing private chat:', username);
    
    const chatTab = document.querySelector(`[data-private-chat="${username}"]`);
    if (chatTab) {
        chatTab.remove();
    }
    
    // Если закрываем активный чат, переключаемся на общий
    if (currentPrivateChatUser === username) {
        currentPrivateChatUser = null;
        switchChat('general');
    }
    
    // Удаляем из кэша
    delete privateChats[username];
}


function highlightPrivateChatTab(username) {
    console.log('Highlight private chat tab for:', username);
}

// Обновленная функция switchChat
function switchChat(chatType, username = null) {
    console.log('Switch to chat:', chatType, username);
    
    document.querySelectorAll('.chat-list-item').forEach(item => {
        item.classList.remove('active');
    });
    
    if (chatType === 'general') {
        document.getElementById('general-chat-tab').classList.add('active');
        document.getElementById('current-chat-title').textContent = 'Общий чат';
        currentPrivateChatUser = null;
        isFavoritesView = false;
        loadMessages(false);
    } else if (chatType === 'favorites') {
        document.getElementById('favorites-chat-tab').classList.add('active');
        document.getElementById('current-chat-title').textContent = 'Избранное';
        currentPrivateChatUser = null;
        isFavoritesView = true;
        loadMessages(true);
    } else if (chatType === 'private' && username) {
        startPrivateChat(username);
    }
    
    const messageInputContainer = document.querySelector('.message-input');
    if (messageInputContainer) {
        messageInputContainer.classList.remove('favorites-collapsed');
    }
}



// Функция для сохранения аватара
async function saveAvatar() {
    const avatarInput = document.getElementById('avatar-input');
    const avatarPreview = document.getElementById('avatar-preview');
    const defaultAvatarPreview = document.getElementById('default-avatar-preview');
    
    let avatarData = null;
    
    // Если выбран файл, конвертируем его в base64
    if (avatarInput.files && avatarInput.files[0]) {
        const file = avatarInput.files[0];
        
        // Проверяем размер файла (максимум 2MB)
        if (file.size > 2 * 1024 * 1024) {
            showNotification('Размер файла не должен превышать 2MB', 'error');
            return;
        }
        
        // Проверяем тип файла
        if (!file.type.startsWith('image/')) {
            showNotification('Пожалуйста, выберите изображение', 'error');
            return;
        }
        
        try {
            avatarData = await fileToBase64(file);
        } catch (error) {
            console.error('Error converting file to base64:', error);
            showNotification('Ошибка при обработке изображения', 'error');
            return;
        }
    } else {
        // Если файл не выбран, используем текущий аватар или генерируем дефолтный
        if (avatarPreview && !avatarPreview.classList.contains('hidden')) {
            avatarData = avatarPreview.src;
        } else {
            // Генерируем дефолтный аватар на основе имени пользователя
            avatarData = generateDefaultAvatar(currentUser.username);
        }
    }
    
    await updateProfile(avatarData, null);
}

// Функция для сохранения описания профиля
async function saveProfileDescription() {
    const aboutMeInput = document.getElementById('about-me-input');
    const aboutMe = aboutMeInput ? aboutMeInput.value.trim() : '';
    
    await updateProfile(null, aboutMe);
}

// Общая функция для обновления профиля
async function updateProfile(avatar, aboutMe) {
    const token = localStorage.getItem('token');
    if (!token) {
        showNotification('Вы не авторизованы', 'error');
        return;
    }

    try {
        showNotification('Сохранение...', 'info');
        
        const response = await fetch(`${API_BASE}/user/profile/update`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                avatar: avatar,
                aboutMe: aboutMe
            })
        });

        const data = await response.json();
        
        if (data.success) {
            // Обновляем данные пользователя в localStorage и currentUser
            if (data.user) {
                localStorage.setItem('user', JSON.stringify(data.user));
                currentUser = data.user;
                
                // Обновляем превью аватара
                displayAvatarPreview(data.user.avatar);
                
                // Обновляем UI лобби
                updateLobbyUI();
            }
            
            showNotification('Профиль успешно обновлен! ✅');
        } else {
            showNotification('Ошибка: ' + data.message, 'error');
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        showNotification('Ошибка при обновлении профиля', 'error');
    }
}

// Вспомогательная функция для конвертации файла в base64
function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
        reader.readAsDataURL(file);
    });
}

// Функция для загрузки данных профиля при открытии настроек
function loadProfileData() {
    if (!currentUser) return;
    
    const aboutMeInput = document.getElementById('about-me-input');
    if (aboutMeInput && currentUser.aboutMe) {
        aboutMeInput.value = currentUser.aboutMe;
    }
    
    displayAvatarPreview(currentUser.avatar);
}

function editMessage() {
    console.log('Edit message function called');
    if (!currentMessageElement) return;
    
    const messageId = currentMessageElement.dataset.messageId;
    const currentText = currentMessageElement.querySelector('.main-message-text').textContent;
    
    editingMessageId = messageId;
    const messageInput = document.getElementById('message-input');
    if (messageInput) {
        messageInput.value = currentText;
        messageInput.focus();
        showNotification('Режим редактирования. Измените текст и нажмите Enter.', 'info');
    }
    
    hideContextMenu();
}

function clearEditState() {
    console.log('Clear edit state function called');
    editingMessageId = null;
    const messageInput = document.getElementById('message-input');
    if (messageInput) {
        messageInput.value = '';
        messageInput.placeholder = 'Напишите сообщение...';
    }
}

function scrollToMessageAndHighlight(messageId) {
    console.log('Scroll to message:', messageId);
    const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
    if (messageElement) {
        messageElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
        messageElement.classList.add('highlighted');
        setTimeout(() => {
            messageElement.classList.remove('highlighted');
        }, 2000);
    }
}

function addToFavorites() {
    if (!currentMessageElement) return;
    
    const messageId = currentMessageElement.dataset.messageId;
    const isFavorite = currentMessageElement.dataset.isFavorite === 'true';
    
    if (!messageId) return;
    
    const token = localStorage.getItem('token');
    if (!token) return;
    
    fetch(`${API_BASE}/message/favorite`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            messageId: parseInt(messageId),
            isFavorite: !isFavorite
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            currentMessageElement.dataset.isFavorite = !isFavorite;
            const favoriteIcon = currentMessageElement.querySelector('.message-favorite-icon');
            if (favoriteIcon) {
                favoriteIcon.classList.toggle('active', !isFavorite);
            }
            showNotification(isFavorite ? 'Убрано из избранного' : 'Добавлено в избранное');
        } else {
            showNotification('Ошибка: ' + data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error updating favorite status:', error);
        showNotification('Ошибка при обновлении избранного', 'error');
    });
}

// НОВАЯ ФУНКЦИЯ loadProfileData
function loadProfileData() {
    if (!currentUser) return;
    
    const aboutMeInput = document.getElementById('about-me-input');
    if (aboutMeInput && currentUser.aboutMe) {
        aboutMeInput.value = currentUser.aboutMe;
    }
    
    displayAvatarPreview(currentUser.avatar);
}

// НОВАЯ ФУНКЦИЯ showContextMenu
function showContextMenu(x, y, messageElement) {
    const contextMenu = document.getElementById('context-menu');
    if (!contextMenu) return;
    
    contextMenu.style.left = x + 'px';
    contextMenu.style.top = y + 'px';
    contextMenu.classList.remove('hidden');
    contextMenuVisible = true;
    
    currentMessageElement = messageElement;
}

// НОВАЯ ФУНКЦИЯ hideContextMenu
function hideContextMenu() {
    const contextMenu = document.getElementById('context-menu');
    if (contextMenu) {
        contextMenu.classList.add('hidden');
    }
    contextMenuVisible = false;
}

// НОВАЯ ФУНКЦИЯ updateMessageFavoriteStatusInDOM
function updateMessageFavoriteStatusInDOM(messageId, isFavorite) {
    const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
    if (messageElement) {
        messageElement.dataset.isFavorite = isFavorite;
        const favoriteIcon = messageElement.querySelector('.message-favorite-icon');
        if (favoriteIcon) {
            favoriteIcon.classList.toggle('active', isFavorite);
        }
    }
}

// Глобальные функции для HTML
window.searchUsers = searchUsers;
window.startPrivateChat = startPrivateChat;
window.closePrivateChat = closePrivateChat;
window.switchToPrivateChat = switchToPrivateChat;
window.login = login;
window.register = register;
window.logout = logout;
window.showLogin = showLogin;
window.showRegister = showRegister;
window.sendMessage = sendMessage;
window.handleKeyPress = handleKeyPress;
window.toggleTheme = toggleTheme;
window.changeTheme = changeTheme;
window.showSettings = showSettings;
window.hideSettings = hideSettings;
window.toggleEmojiPicker = toggleEmojiPicker;
window.hideEmojiPicker = hideEmojiPicker;
window.insertEmoji = insertEmoji;
window.addToFavorites = addToFavorites;
window.editMessage = editMessage;       
window.scrollToMessageAndHighlight = scrollToMessageAndHighlight; 
window.clearEditState = clearEditState; 
window.switchChat = switchChat; 
window.saveAvatar = saveAvatar;
window.generateDefaultAvatar = generateDefaultAvatar;
window.showSettingsTab = showSettingsTab;
window.saveProfileDescription = saveProfileDescription;
window.showProfileModal = showProfileModal;
window.hideProfileModal = hideProfileModal;
window.loadProfileModalData = loadProfileModalData;
window.showImagePreview = showImagePreview;
window.hideImagePreview = hideImagePreview;
window.searchUsers = searchUsers;
window.startPrivateChat = startPrivateChat;
window.highlightPrivateChatTab = highlightPrivateChatTab;
window.replyToMessage = replyToMessage;
window.clearReplyState = clearReplyState;
window.displayAvatarPreview = displayAvatarPreview;
window.handleAvatarChange = handleAvatarChange;
window.updateLobbyUI = updateLobbyUI;
window.toggleUserStatus = toggleUserStatus;
window.updateLobbyUI = updateLobbyUI;





