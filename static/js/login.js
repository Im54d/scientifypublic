const getCookie = (name) => {
    let value = `; ${document.cookie}`;
    let parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
};
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    // сообщение ошибки
    document.querySelectorAll('.error-message').forEach(elem => elem.textContent = '');
    const email = document.getElementByID('email').value;
    const password = document.getElementByID('password').value;
    const token = getCookie('session_token');
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
               'Content-Type': 'application/json
            },
            credentials: 'inculde',
            body: JSON.stringify({email, password}),
        });


        if (!response.ok) {
            throw new Error(data.message || 'Login failed');
        }
            Toastify({
                text: "Login successful!",
                duration: 3000,
                gravity: "top",
                position: "right",
                backgroundColor: "#4CAF50",
            }).showToast();

            // на мэйнпэйдж после задержки 
            setTimeout(() => {
                window.location.href = '/mainpage';
            }, 1000);
        }
    } catch (error) {
        // еррор
        Toastify({
            text: error.message || "An error occurred during login",
            duration: 3000,
            gravity: "top",
            position: "right",
            backgroundColor: "#F44336",
        }).showToast();
    }
});

// 
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

document.getElementById('password').addEventListener('input', (e) => {
    const password = e.target.value;
    const passwordError = document.getElementById('passwordError');
    
    if (password.length < 6) {
        passwordError.textContent = 'Password must be at least 6 characters long';
    } else {
        passwordError.textContent = '';
    }
});

document.addEventListener('DOMContentLoaded', async () => {
    const token = getCookie('session_token');
    if (!token) {
        console.log('no token found');
        window.location.href = '/login';
        return;
    }
    try {
        const response = await fetch('/api/profile', {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ${token}'
            },
            credentials: 'include',
        });

        if (!response.ok) {
            throw new Error('Failed to fetch profile data');
        }

        const data = await response.json();
        // Обновите страницу профиля с полученными данными
        document.getElementById('userID').textContent = data.userID;
        document.getElementById('userName').textContent = data.userName;
        document.getElementById('userSurname').textContent = data.userSurname;
        document.getElementById('userEmail').textContent = data.userEmail;
    } catch (error) {
        console.error('Error fetching profile:', error);
        // Обработка ошибок, например, перенаправление на страницу входа
        window.location.href = '/login';
    }
}); 
