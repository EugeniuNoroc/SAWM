package com.lab.config;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;

/**
 * Создаёт таблицу guest при старте и добавляет пару обычных записей.
 */
@Component
public class DatabaseInitializer {

    private final JdbcTemplate jdbc;

    public DatabaseInitializer(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostConstruct
    public void init() {
        jdbc.execute("DROP TABLE IF EXISTS \"guest\"");
        jdbc.execute(
            "CREATE TABLE \"guest\" (" +
            "  id                 INT AUTO_INCREMENT PRIMARY KEY," +
            "  \"user\"           VARCHAR(50)  NOT NULL," +
            "  text_message       VARCHAR(1000) NOT NULL," +
            "  e_mail             VARCHAR(100)," +
            "  data_time_message  TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );

        jdbc.update("INSERT INTO \"guest\" (\"user\", text_message, e_mail) VALUES (?, ?, ?)",
                "Иван", "Отличная гостевая книга!", "ivan@mail.com");
        jdbc.update("INSERT INTO \"guest\" (\"user\", text_message, e_mail) VALUES (?, ?, ?)",
                "Мария", "Привет всем :)", "maria@mail.com");

        System.out.println("[DB] Таблица \"guest\" создана.");
    }
}
