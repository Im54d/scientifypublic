document.addEventListener("DOMContentLoaded", function() {
    fetch('/api/profile', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        credentials: 'include' // Важно для отправки куки
    })
    .then(response => {
        if (response.redirected) {
            window.location.href = response.url;
            return;
        }
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data) { // Проверяем, что data существует
            document.getElementById('userName').textContent = data.data.user_name;
            document.getElementById('userSurname').textContent = data.data.user_surname;
            document.getElementById('userEmail').textContent = data.data.user_email;
        }
    })
    .catch(error => {
        console.error('Error loading profile data:', error);
        // Перенаправляем на страницу логина только если это ошибка авторизации
        if (error.message === 'Unauthorized') {
            window.location.href = '/login';
        }
    });
});
