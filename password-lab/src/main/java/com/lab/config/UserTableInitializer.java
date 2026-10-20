package com.lab.config;

import jakarta.annotation.PostConstruct;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Создаёт таблицу "user" в ИСХОДНОМ (уязвимом) виде: пароли в открытом тексте.
 * Так обычно выглядит база учебного приложения до доработки.
 * Колонка password имеет длину 255 — её хватает и для строки Argon2id (~97 символов).
 */
@Component
public class UserTableInitializer {

    private final JdbcTemplate jdbc;

    public UserTableInitializer(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostConstruct
    public void init() {
        reset();
        System.out.println("[DB] Таблица \"user\" создана (пароли в открытом виде).");
    }

    public void reset() {
        jdbc.execute("DROP TABLE IF EXISTS \"user\"");
        jdbc.execute(
            "CREATE TABLE \"user\" (" +
            "  id       INT AUTO_INCREMENT PRIMARY KEY," +
            "  login    VARCHAR(50)  NOT NULL UNIQUE," +
            "  password VARCHAR(255) NOT NULL," +
            "  email    VARCHAR(100)" +
            ")");

        String sql = "INSERT INTO \"user\" (login, password, email) VALUES (?, ?, ?)";
        // Специально: у ivan и maria одинаковый пароль, у admin — популярный
        jdbc.update(sql, "admin", "admin123",            "admin@lab.local");
        jdbc.update(sql, "ivan",  "qwerty",              "ivan@mail.com");
        jdbc.update(sql, "maria", "qwerty",              "maria@mail.com");
        jdbc.update(sql, "petr",  "123456",              "petr@mail.com");
        jdbc.update(sql, "elena", "Kot-Lampa-Reka-2026!", "elena@mail.com");
        jdbc.update(sql, "oleg",  "r7#Vq!m2Zp@9xL$w",    "oleg@mail.com");
    }
}
