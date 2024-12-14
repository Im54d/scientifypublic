document.getElementById('registerForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Предотвращаем стандартное поведение формы

    const name = document.getElementById('name').value;
    const surname = document.getElementById('surname').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    fetch('/api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name, surname, email, password, confirmPassword })
    })
    .then(response => {
        if (response.ok) {
            // Успешная регистрация
            window.location.href = '/login'; // Перенаправление на страницу входа
        } else {
            return response.json().then(data => {
                // Обработка ошибок
                if (data.error) {
                    alert(data.error); // Отображение сообщения об ошибке
                }
            });
        }
    })
    .catch(error => console.error('Ошибка:', error));
}); 