package com.lab.controller;

import com.lab.dao.UserDao;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminController {

    private final UserDao userDao;

    public AdminController(UserDao userDao) {
        this.userDao = userDao;
    }

    @GetMapping("/admin")
    public String admin(HttpSession session, Model model) {
        Object user = session.getAttribute("user");
        if (user == null) {
            return "redirect:/login";
        }
        model.addAttribute("user", user);
        model.addAttribute("users", userDao.findAll());
        return "admin";
    }
}
