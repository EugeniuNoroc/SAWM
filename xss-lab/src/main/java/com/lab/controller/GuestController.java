package com.lab.controller;

import com.lab.dao.GuestDao;
import com.lab.util.XssValidator;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class GuestController {

    private final GuestDao guestDao;

    public GuestController(GuestDao guestDao) {
        this.guestDao = guestDao;
    }

    @GetMapping("/")
    public String guestbook(@RequestParam(defaultValue = "true") boolean secure,
                            HttpServletResponse response,
                            Model model) {
        // В защищённом режиме добавляем заголовок CSP — ещё один барьер против XSS
        if (secure) {
            response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'");
        }
        model.addAttribute("secure", secure);
        model.addAttribute("guests", guestDao.findAll());
        return "guestbook";
    }

    @PostMapping("/add")
    public String add(@RequestParam String user,
                      @RequestParam("text_message") String message,
                      @RequestParam(value = "e_mail", required = false) String email,
                      @RequestParam(defaultValue = "true") boolean secure,
                      Model model) {

        if (secure) {
            // Проверка ввода: не пускаем HTML/скрипты в базу
            String error = XssValidator.validate(user, message, email);
            if (error != null) {
                model.addAttribute("error", error);
                model.addAttribute("secure", true);
                model.addAttribute("guests", guestDao.findAll());
                return "guestbook";
            }
        }

        guestDao.insert(user, message, email);
        return "redirect:/?secure=" + secure;
    }
}
