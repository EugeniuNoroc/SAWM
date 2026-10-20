package com.lab.security;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Консольная демонстрация без Spring и без БД (запуск: см. README).
 * Показывает ту же таблицу, что и страница /users: до и после хэширования.
 */
public class ConsoleDemo {

    public static void main(String[] args) {
        Map<String, String> table = new LinkedHashMap<>();
        table.put("admin", "admin123");
        table.put("ivan",  "qwerty");
        table.put("maria", "qwerty");
        table.put("petr",  "123456");
        table.put("elena", "Kot-Lampa-Reka-2026!");
        table.put("oleg",  "r7#Vq!m2Zp@9xL$w");

        String line = "═".repeat(110);
        System.out.println(line + "\n ТАБЛИЦА \"user\" — ПАРОЛИ В ОТКРЫТОМ ВИДЕ\n" + line);
        table.forEach((l, p) -> System.out.printf(" %-6s | %-22s | MD5 без соли: %s%n", l, p, PasswordService.md5Insecure(p)));
        System.out.println(" -> у ivan и maria одинаковый MD5: видно, что пароли совпадают.");

        PasswordService ps = new PasswordService();
        Map<String, String> hashed = new LinkedHashMap<>();
        table.forEach((l, p) -> hashed.put(l, ps.hash(p)));

        System.out.println("\n" + line + "\n ТАБЛИЦА \"user\" — ПОСЛЕ Argon2id + соль\n" + line);
        hashed.forEach((l, h) -> System.out.printf(" %-6s | %s%n", l, h));
        System.out.println(" -> у ivan и maria разные строки: соли разные ("
                + PasswordService.extractSalt(hashed.get("ivan")) + " / "
                + PasswordService.extractSalt(hashed.get("maria")) + ")");

        System.out.println("\n ПРОВЕРКА ВХОДА");
        System.out.println("   elena + верный пароль   -> " + ps.verify("Kot-Lampa-Reka-2026!", hashed.get("elena")));
        System.out.println("   elena + неверный пароль -> " + ps.verify("kot-lampa-reka-2026!", hashed.get("elena")));

        System.out.println("\n ПОЛИТИКА ПАРОЛЕЙ");
        String[][] cases = {
                {"ivan", "qwerty"}, {"petr", "123456"}, {"admin", "admin123"},
                {"user", "P@ssw0rd"}, {"ivan", "ivan2026!Ivan"},
                {"elena", "Kot-Lampa-Reka-2026!"}, {"oleg", "r7#Vq!m2Zp@9xL$w"},
                {"anna", "зелёный слон пьёт чай у реки"}
        };
        for (String[] c : cases) {
            List<String> pr = PasswordService.checkPolicy(c[0], c[1]);
            System.out.printf("   %-30s -> %s%n", c[1], pr.isEmpty() ? "НАДЁЖНЫЙ" : "СЛАБЫЙ: " + String.join(" ", pr));
        }

        long t0 = System.nanoTime();
        for (int i = 0; i < 200_000; i++) PasswordService.md5Insecure("pass" + i);
        double md5 = (System.nanoTime() - t0) / 1e6 / 200_000;
        t0 = System.nanoTime();
        for (int i = 0; i < 5; i++) ps.hash("pass" + i);
        double argon = (System.nanoTime() - t0) / 1e6 / 5;
        System.out.printf("%n СТОИМОСТЬ: один MD5 = %.5f мс, один Argon2id = %.1f мс (в ~%,.0f раз дороже, плюс 19 МиБ памяти)%n",
                md5, argon, argon / md5);
    }
}
