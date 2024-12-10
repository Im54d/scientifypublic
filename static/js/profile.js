document.addEventListener("DOMContentLoaded", function() {
    // Получаем токен из куки
    const getCookie = (name) => {
        let value = `; ${document.cookie}`;
        let parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    };

    const token = getCookie('session_token');

    fetch('/api/profile', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}` // Используем токен из куки
        }
    })
    .then(response => response.json())
        .then(data => {
            document.getElementById('userID').textContent = data.data.user_id;
            document.getElementById('userName').textContent = data.data.user_name;
            document.getElementById('userSurname').textContent = data.data.user_surname;
            document.getElementById('userEmail').textContent = data.data.user_email;
        })
        .catch(error => console.error('Error loading profile data:', error));
});
