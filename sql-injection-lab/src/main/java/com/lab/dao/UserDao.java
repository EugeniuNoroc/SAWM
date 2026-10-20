package com.lab.dao;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class UserDao {

    private final JdbcTemplate jdbc;

    public UserDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public String buildVulnerableSql(String login, String password) {
        return "SELECT * FROM \"user\" WHERE login = '" + login +
               "' AND password = '" + password + "'";
    }

    // Запрос без защиты: ввод склеивается в текст SQL.
    public List<Map<String, Object>> queryVulnerable(String login, String password) {
        String sql = buildVulnerableSql(login, password);
        System.out.println("[SQL] " + sql);
        return jdbc.queryForList(sql);
    }

    public boolean authenticateVulnerable(String login, String password) {
        return !queryVulnerable(login, password).isEmpty();
    }

    // Защищённый запрос: значения передаются как параметры (?).
    public boolean authenticateSecure(String login, String password) {
        String sql = "SELECT COUNT(*) FROM \"user\" WHERE login = ? AND password = ?";
        Integer count = jdbc.queryForObject(sql, Integer.class, login, password);
        return count != null && count > 0;
    }

    public List<Map<String, Object>> querySecure(String login, String password) {
        String sql = "SELECT id, login, password FROM \"user\" WHERE login = ? AND password = ?";
        return jdbc.queryForList(sql, login, password);
    }

    public List<Map<String, Object>> findAll() {
        return jdbc.queryForList("SELECT id, login, password FROM \"user\" ORDER BY id");
    }
}
