package com.lab.dao;

import com.lab.model.Guest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class GuestDao {

    private final JdbcTemplate jdbc;

    public GuestDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private static final RowMapper<Guest> MAPPER = (rs, i) -> {
        Guest g = new Guest();
        g.setId(rs.getInt("id"));
        g.setUser(rs.getString("user"));
        g.setTextMessage(rs.getString("text_message"));
        g.seteMail(rs.getString("e_mail"));
        g.setDataTimeMessage(String.valueOf(rs.getTimestamp("data_time_message")));
        return g;
    };

    public List<Guest> findAll() {
        return jdbc.query(
            "SELECT id, \"user\", text_message, e_mail, data_time_message " +
            "FROM \"guest\" ORDER BY id DESC", MAPPER);
    }

    // Запись через параметры (?) — это защита от SQL-инъекции, не от XSS.
    public void insert(String user, String message, String email) {
        jdbc.update(
            "INSERT INTO \"guest\" (\"user\", text_message, e_mail) VALUES (?, ?, ?)",
            user, message, email);
    }
}
