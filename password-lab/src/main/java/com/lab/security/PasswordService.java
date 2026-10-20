package com.lab.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Работа с паролями.
 *
 * Алгоритм — Argon2id (победитель Password Hashing Competition 2015,
 * стандарт RFC 9106, первый выбор в OWASP Password Storage Cheat Sheet).
 * Параметры по OWASP: память 19 МиБ, 2 итерации, 1 поток, соль 16 байт, хэш 32 байта.
 *
 * Результат хранится одной строкой в формате PHC:
 *   $argon2id$v=19$m=19456,t=2,p=1$<соль base64>$<хэш base64>
 * В строке есть всё для проверки: алгоритм, параметры, соль и сам хэш.
 */
public class PasswordService {

    private static final int SALT_LENGTH = 16;        // байт
    private static final int HASH_LENGTH = 32;        // байт
    private static final int MEMORY_KIB  = 19 * 1024; // 19 МиБ
    private static final int ITERATIONS  = 2;
    private static final int PARALLELISM = 1;

    private static final Base64.Encoder B64 = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final SecureRandom random = new SecureRandom();

    /** Хэш пароля с новой случайной солью (криптостойкий генератор SecureRandom). */
    public String hash(String rawPassword) {
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        byte[] hash = argon2(rawPassword, salt, MEMORY_KIB, ITERATIONS, PARALLELISM, HASH_LENGTH);
        return "$argon2id$v=19$m=" + MEMORY_KIB + ",t=" + ITERATIONS + ",p=" + PARALLELISM
                + "$" + B64.encodeToString(salt) + "$" + B64.encodeToString(hash);
    }

    /**
     * Проверка: берём соль и параметры из сохранённой строки, считаем хэш
     * введённого пароля и сравниваем за постоянное время (MessageDigest.isEqual),
     * чтобы по времени ответа нельзя было угадывать байты хэша.
     */
    public boolean verify(String rawPassword, String stored) {
        if (rawPassword == null || !isHashed(stored)) return false;
        try {
            String[] p = stored.split("\\$");          // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
            int m = 0, t = 0, par = 0;
            for (String kv : p[3].split(",")) {
                int v = Integer.parseInt(kv.substring(2));
                switch (kv.charAt(0)) { case 'm' -> m = v; case 't' -> t = v; case 'p' -> par = v; }
            }
            byte[] salt = B64D.decode(p[4]);
            byte[] expected = B64D.decode(p[5]);
            byte[] actual = argon2(rawPassword, salt, m, t, par, expected.length);
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static byte[] argon2(String password, byte[] salt, int memKib, int iter, int par, int len) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(memKib)
                .withIterations(iter)
                .withParallelism(par)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[len];
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), out);
        return out;
    }

    public static boolean isHashed(String stored) {
        return stored != null && stored.startsWith("$argon2id$") && stored.split("\\$").length == 6;
    }

    /** Соль из строки Argon2 — только чтобы показать её на странице. */
    public static String extractSalt(String stored) {
        return isHashed(stored) ? stored.split("\\$")[4] : "";
    }

    /**
     * MD5 без соли — НЕ использовать для паролей.
     * Нужен только для сравнения: у одинаковых паролей одинаковый MD5,
     * а у Argon2id с солью — разные строки.
     */
    public static String md5Insecure(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Политика паролей (по мотивам NIST SP 800-63B): длина важнее «сложности»,
     * запрет популярных паролей и совпадения с логином.
     * Пустой список — пароль подходит.
     */
    public static List<String> checkPolicy(String login, String password) {
        List<String> problems = new ArrayList<>();
        if (password == null || password.length() < 12) {
            problems.add("Длина меньше 12 символов.");
        }
        if (password != null) {
            String low = password.toLowerCase();
            if (CommonPasswords.contains(low)) {
                problems.add("Пароль из списка самых популярных.");
            }
            if (login != null && !login.isBlank() && low.contains(login.toLowerCase())) {
                problems.add("Пароль содержит логин.");
            }
            int classes = 0;
            if (password.matches(".*\\p{Ll}.*")) classes++; // Хотя бы одна строчная
            if (password.matches(".*\\p{Lu}.*")) classes++; // Хотя бы одна заглавная
            if (password.matches(".*\\d.*")) classes++; // Хотя бы одна цифра
            if (password.matches(".*[^\\p{L}\\d].*")) classes++; // Хотя бы один спецсимвол
            if (password.length() < 16 && classes < 3) {
                problems.add("Пароль короче 16 символов должен содержать 3 типа символов из 4 (строчные, заглавные, цифры, спецсимволы).");
            }
        }
        return problems;
    }
}
