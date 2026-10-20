// Проверка формы на стороне клиента перед отправкой.

const LOGIN_RE    = /^[A-Za-z0-9._-]{3,50}$/;
const PASSWORD_RE = /^[A-Za-z0-9!@#$%^&*()_+=\-]{6,100}$/;
const SQLI_RE = /('|"|--|#|;|\/\*|\*\/|=|\bor\b\s+\d+=\d+|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b)/i;

function showClientError(message) {
    const box = document.getElementById('clientError');
    box.textContent = message;
    box.style.display = 'block';
}

function validateForm() {
    const login = document.getElementById('login').value.trim();
    const password = document.getElementById('password').value;

    const secure = document.querySelector('input[name="secure"]:checked').value === 'true';
    if (!secure) {
        return true;
    }

    if (login === '' || password === '') {
        showClientError('Заполните логин и пароль.');
        return false;
    }
    if (SQLI_RE.test(login) || SQLI_RE.test(password)) {
        showClientError('Недопустимые символы во вводе.');
        return false;
    }
    if (!LOGIN_RE.test(login)) {
        showClientError('Логин: 3–50 символов (латиница, цифры, . _ -).');
        return false;
    }
    if (!PASSWORD_RE.test(password)) {
        showClientError('Пароль: 6–100 символов без пробелов и кавычек.');
        return false;
    }
    return true;
}
