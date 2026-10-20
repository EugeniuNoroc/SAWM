package com.lab.config;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;

/**
 * Создаёт таблицу user и добавляет начальные записи при старте приложения.
 */
@Component
public class DatabaseInitializer {

    private final JdbcTemplate jdbc;

    public DatabaseInitializer(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostConstruct
    public void init() {
        jdbc.execute("DROP TABLE IF EXISTS \"user\"");
        jdbc.execute(
            "CREATE TABLE \"user\" (" +
            "  id       INT AUTO_INCREMENT PRIMARY KEY," +
            "  login    VARCHAR(50)  NOT NULL UNIQUE," +
            "  password VARCHAR(100) NOT NULL" +
            ")"
        );

        Object[][] users = {
            {"admin",    "Adm1n_P@ss"},
            {"ivanov",   "qwerty123"},
            {"petrov",   "Petrov2024"},
            {"sidorova", "Sid0r0va!"},
            {"manager",  "Manager#99"},
            {"editor",   "Edit0r_pwd"},
            {"guest",    "Guest_000"}
        };

        for (Object[] u : users) {
            jdbc.update("INSERT INTO \"user\" (login, password) VALUES (?, ?)", u[0], u[1]);
        }

        System.out.println("[DB] Таблица \"user\" создана, добавлено " + users.length + " записей.");
    }
}
