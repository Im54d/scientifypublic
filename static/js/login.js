document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    // сообщение ошибки
    document.querySelectorAll('.error-message').forEach(elem => elem.textContent = '');

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Login failed');
        }

        if (data.success) {
            // Хранение токена и данных юзера
            localStorage.setItem('token', data.data.token);
            localStorage.setItem('user', JSON.stringify(data.data.user));

            // подтверждение входа
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