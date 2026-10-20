package com.lab.util;

import java.util.regex.Pattern;

/**
 * Защита от XSS: экранирование вывода и проверка ввода.
 */
public final class XssValidator {

    private static final Pattern EMAIL =
            Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    // Признаки попытки внедрить код
    private static final Pattern XSS_SIGNATURE = Pattern.compile(
            "(?i)(<\\s*script|</\\s*script|<\\s*img|<\\s*iframe|on\\w+\\s*=|javascript:|<|>)");

    private XssValidator() { }

    /**
     * Экранирование спецсимволов HTML — главный приём защиты.
     * После него теги превращаются в безопасный текст и не выполняются.
     */
    public static String escape(String input) {
        if (input == null) return "";
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;")
                .replace("/", "&#47;");
    }

    public static boolean containsXss(String value) {
        return value != null && XSS_SIGNATURE.matcher(value).find();
    }

    /** Возвращает текст ошибки, либо null если данные корректны. */
    public static String validate(String user, String message, String email) {
        if (user == null || user.isBlank() || message == null || message.isBlank()) {
            return "Имя и сообщение обязательны.";
        }
        if (containsXss(user) || containsXss(message)) {
            return "Ввод содержит HTML/скрипт — запрещено.";
        }
        if (email != null && !email.isBlank() && !EMAIL.matcher(email).matches()) {
            return "Некорректный e-mail.";
        }
        return null;
    }
}
