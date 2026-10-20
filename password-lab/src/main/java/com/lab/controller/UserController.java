package com.lab.controller;

import com.lab.config.UserTableInitializer;
import com.lab.dao.UserDao;
import com.lab.model.User;
import com.lab.security.PasswordService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;

@Controller
public class UserController {

    private final UserDao userDao;
    private final PasswordService passwords;
    private final UserTableInitializer initializer;

    public UserController(UserDao userDao, PasswordService passwords, UserTableInitializer initializer) {
        this.userDao = userDao;
        this.passwords = passwords;
        this.initializer = initializer;
    }

    /** п.2 — вывод содержимого таблицы "user". */
    @GetMapping("/users")
    public String users(Model model) {
        List<User> users = userDao.findAll();
        boolean anyPlain = users.stream().anyMatch(u -> !PasswordService.isHashed(u.getPassword()));
        model.addAttribute("users", users);
        model.addAttribute("anyPlain", anyPlain);
        return "users";
    }

    /** п.6 — миграция: все пароли в открытом виде заменяются на Argon2id с солью. */
    @PostMapping("/users/hash")
    public String hashAll(RedirectAttributes ra) {
        int n = 0;
        for (User u : userDao.findAll()) {
            if (!PasswordService.isHashed(u.getPassword())) {
                userDao.updatePassword(u.getId(), passwords.hash(u.getPassword()));
                n++;
            }
        }
        ra.addFlashAttribute("ok", "Захэшировано паролей: " + n + ".");
        return "redirect:/users";
    }

    /** Вернуть таблицу в исходное (уязвимое) состояние — для повторной демонстрации. */
    @PostMapping("/users/reset")
    public String reset(RedirectAttributes ra) {
        initializer.reset();
        ra.addFlashAttribute("ok", "Таблица восстановлена.");
        return "redirect:/users";
    }

    /** Регистрация: политика паролей + хэширование перед записью в БД. */
    @PostMapping("/users/register")
    public String register(@RequestParam String login, @RequestParam String password,
                           @RequestParam(required = false) String email, RedirectAttributes ra) {
        if (login.isBlank() || !login.matches("[A-Za-z0-9_.-]{3,50}")) {
            ra.addFlashAttribute("error", "Логин: 3–50 символов (латиница, цифры, _ . -).");
            return "redirect:/users";
        }
        if (userDao.findByLogin(login).isPresent()) {
            ra.addFlashAttribute("error", "Такой логин уже есть.");
            return "redirect:/users";
        }
        List<String> problems = PasswordService.checkPolicy(login, password);
        if (!problems.isEmpty()) {
            ra.addFlashAttribute("error", "Слабый пароль: " + String.join(" ", problems));
            return "redirect:/users";
        }
        userDao.insert(login, passwords.hash(password), email);
        ra.addFlashAttribute("ok", "Пользователь «" + login + "» создан.");
        return "redirect:/users";
    }

    /** Вход: проверка пароля через verify(), сравнение с хэшем, а не с текстом. */
    @PostMapping("/users/login")
    public String login(@RequestParam String login, @RequestParam String password, RedirectAttributes ra) {
        Optional<User> u = userDao.findByLogin(login);
        if (u.isPresent() && !PasswordService.isHashed(u.get().getPassword())) {
            ra.addFlashAttribute("error", "Пароли ещё не захэшированы — сначала нажмите «Захэшировать».");
            return "redirect:/users";
        }
        boolean ok = u.isPresent() && passwords.verify(password, u.get().getPassword());
        // Одно и то же сообщение для «нет логина» и «неверный пароль» — не раскрываем, какие логины существуют
        if (ok) ra.addFlashAttribute("ok", "Вход выполнен: " + login);
        else    ra.addFlashAttribute("error", "Неверный логин или пароль.");
        return "redirect:/users";
    }
}