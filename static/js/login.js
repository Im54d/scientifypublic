// Обработчик формы входа
// Сохранение токена в куки и последующая работа с ним

document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();

    document.querySelectorAll('.error-message').forEach(elem => elem.textContent = '');

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    console.log('Attempting login with:', email); // Для отладки

    fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Server response:', data); // Для отладки

        if (data.success) {
            
            window.location.href = '/mainpage';
        } else {
            throw new Error(data.message || 'Login failed');
        }
    })
    .catch(error => {
        console.error('Login error:', error);
        alert(error.message);
    });
});

// Валидация email
document.getElementById('email').addEventListener('input', (e) => {
    const email = e.target.value;
    const emailError = document.getElementById('emailError');
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!emailRegex.test(email)) {
        emailError.textContent = 'Please enter a valid email address';
    } else {
        emailError.textContent = '';
    }
});

// Валидация пароля
document.getElementById('password').addEventListener('input', (e) => {
    const password = e.target.value;
    const passwordError = document.getElementById('passwordError');
    
    if (password.length < 6) {
        passwordError.textContent = 'Password must be at least 6 characters long';
    } else {
        passwordError.textContent = '';
    }
});

// Получение токена из cookies
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Проверка токена при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    const token = getCookie('session_token');
    console.log('Token from cookie:', token);

    if (!token) {
        if (window.location.pathname !== '/login') {
            window.location.href = '/login';
        }
    }

    if (window.location.pathname === '/mainpage') {
        fetchProfileData();
    }
});

function fetchProfileData() {
    fetch('/api/profile', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${getCookie('session_token')}`
        }
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        } else {
            throw new Error('Failed to fetch profile');
        }
    })
    .then(data => {
        document.getElementById('userID').textContent = data.userID;
        document.getElementById('userName').textContent = data.userName;
        document.getElementById('userSurname').textContent = data.userSurname;
        document.getElementById('userEmail').textContent = data.userEmail;
    })
    .catch(error => {
        console.error('Error fetching profile:', error);
        window.location.href = '/login';
    });
}

// Функция для получения токена из cookies
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function handleLogin() {
    // Удаление старого токена из локального хранилища
    localStorage.removeItem('token');

    // Получение нового токена из куки
    const token = getCookie('session_token');
    localStorage.setItem('token', token); // Сохранение нового токена
}

console.log('Using token:', token);
