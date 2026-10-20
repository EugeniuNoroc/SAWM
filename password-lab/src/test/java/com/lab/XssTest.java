package com.lab;

import com.lab.dao.GuestDao;
import com.lab.model.Guest;
import com.lab.util.XssValidator;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты: проверяют защиту от XSS (экранирование вывода и проверка ввода).
 */
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class XssTest {

    @Autowired
    private GuestDao guestDao;

    private static final String LINE =
            "══════════════════════════════════════════════════════════════════";

    private static final String[] PAYLOADS = {
            "<script>window.location='https://example.com'</script>",
            "<script>document.body.innerHTML='<img src=x>'</script>",
            "<img src=x onerror=alert(1)>",
            "<iframe src='javascript:alert(1)'></iframe>"
    };

    @Test @Order(1)
    @DisplayName("1) АТАКА: без экранирования скрипт попадает в HTML как есть")
    void payloadStoredRaw() {
        System.out.println("\n" + LINE);
        System.out.println(" ТЕСТ 1. БЕЗ ЗАЩИТЫ — ввод выводится как HTML");
        System.out.println(LINE);

        String payload = PAYLOADS[0];
        guestDao.insert("hacker", payload, "h@h.h");
        Guest saved = guestDao.findAll().get(0);

        System.out.println(" Сохранено в БД: " + saved.getTextMessage());
        System.out.println(" В режиме без защиты это попадёт в страницу тегом <script>");
        System.out.println(" и выполнится в браузере -> редирект / подмена страницы.");
        System.out.println(LINE);

        assertTrue(saved.getTextMessage().contains("<script"),
                "В БД payload хранится как есть (опасен при выводе без экранирования)");
    }

    @Test @Order(2)
    @DisplayName("2) ЗАЩИТА: экранирование превращает теги в безопасный текст")
    void escapeNeutralizes() {
        System.out.println("\n" + LINE);
        System.out.println(" ТЕСТ 2. ЭКРАНИРОВАНИЕ ВЫВОДА (главный приём)");
        System.out.println(LINE);

        for (String p : PAYLOADS) {
            String safe = XssValidator.escape(p);
            boolean hasTag = safe.contains("<script") || safe.contains("<img") || safe.contains("<iframe");
            System.out.println(" ввод : " + p);
            System.out.println(" вывод: " + safe);
            System.out.println(" содержит рабочий тег? " + (hasTag ? "ДА !!!" : "НЕТ"));
            System.out.println(" ----");
            assertFalse(hasTag, "После экранирования тег не должен остаться рабочим");
        }
        System.out.println(" ВЫВОД: >>> теги стали текстом, браузер их не исполняет <<<");
        System.out.println(LINE);
    }

    @Test @Order(3)
    @DisplayName("3) ЗАЩИТА: проверка ввода отклоняет HTML/скрипты")
    void validatorRejects() {
        System.out.println("\n" + LINE);
        System.out.println(" ТЕСТ 3. ПРОВЕРКА ВВОДА (не пускаем теги в базу)");
        System.out.println(LINE);
        for (String p : PAYLOADS) {
            String err = XssValidator.validate("user", p, "a@b.c");
            System.out.printf("   %-55s -> %s%n",
                    p.length() > 55 ? p.substring(0, 52) + "..." : p,
                    err == null ? "ПРОПУЩЕНО !!!" : "ОТКЛОНЕНО");
            assertNotNull(err, "Валидатор должен отклонить: " + p);
        }
        System.out.println(LINE);
    }

    @Test @Order(4)
    @DisplayName("4) КОРРЕКТНОСТЬ: обычное сообщение проходит")
    void normalPasses() {
        System.out.println("\n" + LINE);
        System.out.println(" ТЕСТ 4. ОБЫЧНАЯ ЗАПИСЬ");
        System.out.println(LINE);
        String err = XssValidator.validate("Иван", "Хорошая книга!", "ivan@mail.com");
        System.out.println("   'Хорошая книга!' -> " + (err == null ? "ПРИНЯТО" : "ОТКЛОНЕНО: " + err));
        System.out.println(LINE + "\n");
        assertNull(err, "Обычный текст должен проходить");
    }
}
