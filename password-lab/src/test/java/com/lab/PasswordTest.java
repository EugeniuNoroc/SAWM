package com.lab;

import com.lab.config.UserTableInitializer;
import com.lab.dao.UserDao;
import com.lab.model.User;
import com.lab.security.PasswordService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Лаб. 4: пароли в открытом виде -> Argon2id с солью. Печатает отчёт в консоль. */
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PasswordTest {

    @Autowired private UserDao userDao;
    @Autowired private PasswordService passwords;
    @Autowired private UserTableInitializer initializer;

    private static final String LINE = "══════════════════════════════════════════════════════════════════════════";

    private void printTable(String title) {
        System.out.println("\n" + LINE + "\n " + title + "\n" + LINE);
        for (User u : userDao.findAll()) {
            System.out.printf(" %-2d %-6s %s%n", u.getId(), u.getLogin(), u.getPassword());
        }
        System.out.println(LINE);
    }

    @Test @Order(1)
    @DisplayName("1) Исходная таблица user: пароли в открытом виде")
    void plainTable() {
        initializer.reset();
        printTable("ТЕСТ 1. ТАБЛИЦА \"user\" ДО ЗАЩИТЫ (пароли видны как есть)");
        assertEquals("admin123", userDao.findByLogin("admin").orElseThrow().getPassword());
    }

    @Test @Order(2)
    @DisplayName("2) MD5 без соли: одинаковые пароли дают одинаковый хэш")
    void md5SameHash() {
        String a = PasswordService.md5Insecure("qwerty");
        String b = PasswordService.md5Insecure("qwerty");
        System.out.println("\n ТЕСТ 2. MD5('qwerty') у ivan  = " + a);
        System.out.println("         MD5('qwerty') у maria = " + b);
        System.out.println("         -> совпадают: по одному хэшу видно, у кого общий пароль.");
        assertEquals(a, b);
    }

    @Test @Order(3)
    @DisplayName("3) Миграция на Argon2id с солью")
    void migrate() {
        initializer.reset();
        for (User u : userDao.findAll()) {
            userDao.updatePassword(u.getId(), passwords.hash(u.getPassword()));
        }
        printTable("ТЕСТ 3. ТАБЛИЦА \"user\" ПОСЛЕ Argon2id + соль");
        List<User> all = userDao.findAll();
        assertTrue(all.stream().allMatch(u -> PasswordService.isHashed(u.getPassword())));

        String ivan = userDao.findByLogin("ivan").orElseThrow().getPassword();
        String maria = userDao.findByLogin("maria").orElseThrow().getPassword();
        System.out.println(" Соль ivan : " + PasswordService.extractSalt(ivan));
        System.out.println(" Соль maria: " + PasswordService.extractSalt(maria));
        System.out.println(" Пароль одинаковый, хэши разные: " + !ivan.equals(maria));
        assertNotEquals(ivan, maria, "Соль делает хэши одинаковых паролей разными");
    }

    @Test @Order(4)
    @DisplayName("4) Вход работает: verify() проверяет пароль по хэшу")
    void verify() {
        String stored = userDao.findByLogin("elena").orElseThrow().getPassword();
        boolean good = passwords.verify("Kot-Lampa-Reka-2026!", stored);
        boolean bad = passwords.verify("kot-lampa-reka-2026!", stored);
        System.out.println("\n ТЕСТ 4. Верный пароль -> " + good + ", неверный (другой регистр) -> " + bad);
        assertTrue(good);
        assertFalse(bad);
    }

    @Test @Order(5)
    @DisplayName("5) Политика паролей: слабые отклоняются, надёжные проходят")
    void policy() {
        System.out.println("\n ТЕСТ 5. ПОЛИТИКА ПАРОЛЕЙ");
        String[][] cases = {
                {"ivan", "qwerty"}, {"petr", "123456"}, {"admin", "admin123"},
                {"ivan", "ivan2026!Ivan"}, {"user", "P@ssw0rd"},
                {"elena", "Kot-Lampa-Reka-2026!"}, {"oleg", "r7#Vq!m2Zp@9xL$w"},
                {"anna", "зелёный слон пьёт чай у реки"}
        };
        for (String[] c : cases) {
            List<String> p = PasswordService.checkPolicy(c[0], c[1]);
            System.out.printf("   %-32s -> %s%n", c[1], p.isEmpty() ? "НАДЁЖНЫЙ" : "СЛАБЫЙ: " + String.join(" ", p));
        }
        assertFalse(PasswordService.checkPolicy("ivan", "qwerty").isEmpty());
        assertTrue(PasswordService.checkPolicy("oleg", "r7#Vq!m2Zp@9xL$w").isEmpty());
        assertTrue(PasswordService.checkPolicy("anna", "зелёный слон пьёт чай у реки").isEmpty());
    }

    @Test @Order(6)
    @DisplayName("6) Стоимость вычисления: Argon2id намеренно медленный")
    void cost() {
        long t0 = System.nanoTime();
        for (int i = 0; i < 100_000; i++) PasswordService.md5Insecure("pass" + i);
        double md5Each = (System.nanoTime() - t0) / 1e6 / 100_000;
        t0 = System.nanoTime();
        for (int i = 0; i < 5; i++) passwords.hash("pass" + i);
        double argonEach = (System.nanoTime() - t0) / 1e6 / 5;
        System.out.printf("%n ТЕСТ 6. Один MD5: %.5f мс, один Argon2id: %.1f мс (в ~%,.0f раз дороже)%n",
                md5Each, argonEach, argonEach / md5Each);
        assertTrue(argonEach > md5Each * 100);
    }
}
