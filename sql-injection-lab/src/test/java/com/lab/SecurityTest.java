package com.lab;

import com.lab.dao.UserDao;
import com.lab.util.InputValidator;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты безопасности: проверяют поведение при SQL-инъекции и при обычном входе.
 */
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SecurityTest {

    @Autowired
    private UserDao userDao;

    private static final String LINE =
            "══════════════════════════════════════════════════════════════════";

    private static final String[] INJECTIONS = {
            "admin' --",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "' OR '1'='1",
            "x' UNION SELECT 1,2,3 --"
    };

    // ────────────────────────────────────────────────────────────────────
    @Test @Order(1)
    @DisplayName("1) АТАКА: инъекция вытаскивает данные из уязвимого метода")
    void injectionBreaksVulnerableMethod() {
        String attackLogin = "' OR '1'='1' --";
        String attackPass  = "неверный_пароль";

        System.out.println("\n" + LINE);
        System.out.println(" ТЕСТ 1. АТАКА НА УЯЗВИМЫЙ МЕТОД (ввод склеивается в SQL)");
        System.out.println(LINE);
        System.out.println(" Злоумышленник вводит:");
        System.out.println("   login    = " + attackLogin);
        System.out.println("   password = " + attackPass + "   (пароль НЕ знает!)");
        System.out.println(" Итоговый запрос к БД:");
        System.out.println("   " + userDao.buildVulnerableSql(attackLogin, attackPass));

        List<Map<String, Object>> leaked = userDao.queryVulnerable(attackLogin, attackPass);
        long totalInDb = userDao.findAll().size();

        System.out.println(" ─ РЕЗУЛЬТАТ ИЗ БАЗЫ ──────────────────────────────────");
        System.out.println("   Запрос вернул строк : " + leaked.size() + " из " + totalInDb + " (вся таблица!)");
        System.out.print  ("   Утекшие логины      : ");
        leaked.forEach(r -> System.out.print(r.get("LOGIN") + " "));
        System.out.println();
        System.out.println("   Вход разрешён?      : " + (leaked.isEmpty() ? "НЕТ" : "ДА"));
        System.out.println("   ВЫВОД: >>> УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА — вход без пароля + утечка данных <<<");
        System.out.println(LINE);

        assertEquals(totalInDb, leaked.size(),
                "Инъекция должна вернуть все строки таблицы (утечка данных)");
        assertTrue(userDao.authenticateVulnerable(attackLogin, attackPass));
    }

    // ────────────────────────────────────────────────────────────────────
    @Test @Order(2)
    @DisplayName("2) ЗАЩИТА: та же инъекция не работает в безопасном методе")
    void injectionBlockedBySecureMethod() {
        System.out.println("\n" + LINE);
        System.out.println(" ТЕСТ 2. ТА ЖЕ АТАКА НА ЗАЩИЩЁННЫЙ МЕТОД (PreparedStatement)");
        System.out.println(LINE);
        System.out.println(" Значения передаются как ДАННЫЕ через '?', а не как часть SQL.");
        System.out.printf ("   %-28s | %-6s | %s%n", "Инъекция", "строк", "вход");
        System.out.println("   ----------------------------+--------+-------");

        for (String payload : INJECTIONS) {
            List<Map<String, Object>> rows = userDao.querySecure(payload, "неверный_пароль");
            boolean granted = !rows.isEmpty();
            System.out.printf("   %-28s | %-6d | %s%n", payload, rows.size(), granted ? "ДА" : "НЕТ");
            assertFalse(granted, "PreparedStatement не должен пускать по инъекции: " + payload);
        }

        System.out.println(" ВЫВОД: >>> ВСЕ инъекции вернули 0 строк — доступ запрещён, утечки нет <<<");
        System.out.println(LINE);
    }

    // ────────────────────────────────────────────────────────────────────
    @Test @Order(3)
    @DisplayName("3) ЗАЩИТА: серверный валидатор отклоняет вредоносный ввод")
    void validatorRejectsInjection() {
        System.out.println("\n" + LINE);
        System.out.println(" ТЕСТ 3. СЕРВЕРНАЯ ВАЛИДАЦИЯ ВВОДА (белый список)");
        System.out.println(LINE);

        for (String payload : INJECTIONS) {
            String error = InputValidator.validateCredentials(payload, "pass123");
            System.out.printf("   %-28s -> %s%n", payload, error == null ? "ПРОПУЩЕНО !!!" : "ОТКЛОНЕНО");
            assertNotNull(error, "Валидатор должен отклонить: " + payload);
        }

        System.out.println(" ВЫВОД: >>> вредоносный ввод не доходит даже до запроса <<<");
        System.out.println(LINE);
    }

    // ────────────────────────────────────────────────────────────────────
    @Test @Order(4)
    @DisplayName("4) КОРРЕКТНОСТЬ: верные данные проходят, неверный пароль — нет")
    void legitimateCredentialsWork() {
        System.out.println("\n" + LINE);
        System.out.println(" ТЕСТ 4. ЧЕСТНЫЙ ВХОД (защищённый метод не ломает обычную работу)");
        System.out.println(LINE);

        boolean okValid   = userDao.authenticateSecure("admin", "Adm1n_P@ss");
        boolean okWrong   = userDao.authenticateSecure("admin", "wrong");
        String  valErr    = InputValidator.validateCredentials("admin", "Adm1n_P@ss");

        System.out.println("   admin / Adm1n_P@ss (верный)   -> вход: " + (okValid ? "ДА" : "НЕТ")
                + ", валидатор: " + (valErr == null ? "OK" : valErr));
        System.out.println("   admin / wrong      (неверный) -> вход: " + (okWrong ? "ДА" : "НЕТ"));
        System.out.println(" ВЫВОД: >>> настоящий пользователь входит, подбор пароля — нет <<<");
        System.out.println(LINE + "\n");

        assertTrue(okValid,  "Верные данные должны пускать");
        assertFalse(okWrong, "Неверный пароль не должен пускать");
        assertNull(valErr,   "Валидатор не должен ругаться на корректные данные");
    }
}
