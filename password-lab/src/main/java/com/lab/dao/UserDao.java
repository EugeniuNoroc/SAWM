package com.lab.dao;

import com.lab.model.User;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public class UserDao {

    private final JdbcTemplate jdbc;

    public UserDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private static final RowMapper<User> MAPPER = (rs, i) -> {
        User u = new User();
        u.setId(rs.getInt("id"));
        u.setLogin(rs.getString("login"));
        u.setPassword(rs.getString("password"));
        u.setEmail(rs.getString("email"));
        return u;
    };

    public List<User> findAll() {
        return jdbc.query("SELECT id, login, password, email FROM \"user\" ORDER BY id", MAPPER);
    }

    public Optional<User> findByLogin(String login) {
        return jdbc.query("SELECT id, login, password, email FROM \"user\" WHERE login = ?", MAPPER, login)
                .stream().findFirst();
    }

    public void insert(String login, String password, String email) {
        jdbc.update("INSERT INTO \"user\" (login, password, email) VALUES (?, ?, ?)", login, password, email);
    }

    public void updatePassword(int id, String password) {
        jdbc.update("UPDATE \"user\" SET password = ? WHERE id = ?", password, id);
    }
}
