package com.lab.security;

import java.util.Set;

/** Небольшой список самых популярных паролей. */
final class CommonPasswords {
    private static final Set<String> LIST = Set.of(
            "123456", "123456789", "12345678", "12345", "1234567", "111111",
            "password", "password1", "qwerty", "qwerty123", "qwertyuiop", "abc123",
            "admin", "admin123", "letmein", "welcome", "iloveyou", "monkey",
            "dragon", "football", "000000", "1q2w3e4r", "1qaz2wsx", "zaq12wsx",
            "passw0rd", "p@ssw0rd", "p@ssword", "parola", "parola123"
    );

    private CommonPasswords() { }

    static boolean contains(String lowerPassword) {
        return LIST.contains(lowerPassword);
    }
}
