// Клиентская проверка формы: не даём отправить HTML/скрипт.

const XSS_RE = /(<\s*script|<\s*img|<\s*iframe|on\w+\s*=|javascript:|<|>)/i;

function showClientError(message) {
    const box = document.getElementById('clientError');
    box.textContent = message;
    box.style.display = 'block';
}

function validateForm() {
    const secure = document.querySelector('input[name="secure"]').value === 'true';
    if (!secure) {
        return true; // режим без защиты — пропускаем для демонстрации
    }

    const user = document.getElementById('user').value.trim();
    const message = document.getElementById('text_message').value.trim();

    if (user === '' || message === '') {
        showClientError('Заполните имя и сообщение.');
        return false;
    }
    if (XSS_RE.test(user) || XSS_RE.test(message)) {
        showClientError('HTML-теги и скрипты недопустимы.');
        return false;
    }
    return true;
}
