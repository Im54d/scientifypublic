// Обработчик формы входа
// Сохранение токена в куки и последующая работа с ним

document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();

    // Очистка сообщений об ошибках
    document.querySelectorAll('.error-message').forEach(elem => elem.textContent = '');

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    console.log('Email:', email, 'Password:', password);

    // Отправка данных на сервер для аутентификации
    fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        } else {
            throw new Error('Ошибка входа');
        }
    })
    .then(data => {
        // Сохранение токена в cookie
        document.cookie = `token=${data.token}; path=/; Secure;`;
        console.log('Успешный вход');
        window.location.href = '/mainpage'; // Перенаправление на главную страницу
    })
    .catch(error => console.error('Ошибка:', error));
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

// Проверка токена и загрузка профиля
document.addEventListener('DOMContentLoaded', () => {
    const token = getCookie('token');

    if (!token) {
        // Если нет токена, остаемся на странице логина
        if (window.location.pathname !== '/login') {
            window.location.href = '/login';
        }
        return;
    }

    // Проверка текущего пути и вызов функции fetchProfileData
    if (window.location.pathname === '/mainpage') {
        fetchProfileData(); // Получение профиля только на странице mainpage
    }
});

function fetchProfileData() {
    fetch('/api/profile', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + getCookie('token')
        }
    })
    .then(response => response.json())
    .then(data => {
        // Обновление элементов на странице mainpage
        document.getElementById('userID').textContent = data.userID;
        document.getElementById('userName').textContent = data.userName;
        document.getElementById('userSurname').textContent = data.userSurname;
        document.getElementById('userEmail').textContent = data.userEmail;
    })
    .catch(error => {
        console.error('Error fetching profile:', error);
        window.location.href = '/login'; // Перенаправление на логин при ошибке
    });
}

// Функция для получения токена из cookies
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}
