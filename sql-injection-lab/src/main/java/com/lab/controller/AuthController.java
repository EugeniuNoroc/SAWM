package com.lab.controller;

import com.lab.dao.UserDao;
import com.lab.util.InputValidator;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    private final UserDao userDao;

    public AuthController(UserDao userDao) {
        this.userDao = userDao;
    }

    @GetMapping({"/", "/login"})
    public String loginForm(Model model) {
        model.addAttribute("secure", true);
        return "login";
    }

    @PostMapping("/login")
    public String doLogin(@RequestParam String login,
                          @RequestParam String password,
                          @RequestParam(defaultValue = "true") boolean secure,
                          HttpSession session,
                          Model model) {

        model.addAttribute("secure", secure);
        model.addAttribute("login", login);

        boolean authenticated;

        if (secure) {
            String error = InputValidator.validateCredentials(login, password);
            if (error != null) {
                model.addAttribute("error", error);
                return "login";
            }
            authenticated = userDao.authenticateSecure(login, password);
        } else {
            authenticated = userDao.authenticateVulnerable(login, password);
        }

        if (authenticated) {
            session.setAttribute("user", login);
            return "redirect:/admin";
        }

        model.addAttribute("error", "Неверный логин или пароль.");
        return "login";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }
}
