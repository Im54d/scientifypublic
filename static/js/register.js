document.getElementById('registerForm').addEventListener('submit', function(event) {
    event.preventDefault();

    // Очистка сообщений об ошибках
    document.querySelectorAll('.error-message').forEach(elem => elem.textContent = '');

    const userData = {
        user_name: document.getElementById('name').value,
        user_surname: document.getElementById('surname').value,
        user_email: document.getElementById('email').value,
        user_password_hash: document.getElementById('password').value
    };

    console.log("Sending user data:", JSON.stringify(userData)); 

    fetch('/user_reg', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
    })
    .then(response => {
        if (response.ok) {
            // Если регистрация успешна, перенаправляем на страницу логина
            window.location.href = '/login';
        } else {
            return response.json().then(data => {
                // Обработка ошибок, если регистрация не удалась
                throw new Error(data.message || 'Ошибка регистрации');
            });
        }
    })
    .then(data => {
        console.log('Registration successful:', data);
    })
    .catch(error => {
        console.error('Ошибка:', error);
        // Здесь можно отобразить сообщение об ошибке на странице
    });
});

// Валидация email
document.getElementById('email').addEventListener('input', (e) => {
    const email = e.target.value;
    const emailError = document.getElementById('emailError');
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!emailRegex.test(email)) {
        emailError.textContent = 'Некорректный email';
    } else {
        emailError.textContent = '';
    }
}); 