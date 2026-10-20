package com.lab.util;

import java.util.regex.Pattern;

/**
 * Серверная проверка логина и пароля перед обращением к базе.
 */
public final class InputValidator {

    private static final Pattern LOGIN_PATTERN =
            Pattern.compile("^[A-Za-z0-9._-]{3,50}$");

    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^[A-Za-z0-9!@#$%^&*()_+=\\-]{6,100}$");

    private static final Pattern SQLI_SIGNATURE = Pattern.compile(
            "(?i)(\\bor\\b\\s+\\d+=\\d+|--|#|;|/\\*|\\*/|\\bunion\\b|\\bselect\\b|" +
            "\\bdrop\\b|\\binsert\\b|\\bupdate\\b|\\bdelete\\b|'|\"|=)"
    );

    private InputValidator() { }

    public static boolean isValidLogin(String login) {
        return login != null && LOGIN_PATTERN.matcher(login).matches();
    }

    public static boolean isValidPassword(String password) {
        return password != null && PASSWORD_PATTERN.matcher(password).matches();
    }

    public static boolean looksLikeSqlInjection(String value) {
        return value != null && SQLI_SIGNATURE.matcher(value).find();
    }

    /** Возвращает текст ошибки, либо null если данные корректны. */
    public static String validateCredentials(String login, String password) {
        if (login == null || password == null || login.isBlank() || password.isBlank()) {
            return "Логин и пароль не должны быть пустыми.";
        }
        if (looksLikeSqlInjection(login) || looksLikeSqlInjection(password)) {
            return "Обнаружены недопустимые символы.";
        }
        if (!isValidLogin(login)) {
            return "Логин: 3–50 символов (латиница, цифры, . _ -).";
        }
        if (!isValidPassword(password)) {
            return "Пароль: 6–100 символов без пробелов и кавычек.";
        }
        return null;
    }
}
