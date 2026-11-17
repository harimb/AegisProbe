package com.aegisprobe.user.web;

import com.aegisprobe.user.domain.AppUser;
import com.aegisprobe.user.repository.AppUserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String registerForm() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password, Model model) {
        if (password.length() < 8) {
            model.addAttribute("error", "Password must be at least 8 characters.");
            return "register";
        }
        if (users.existsByUsername(username)) {
            model.addAttribute("error", "That username is already taken.");
            return "register";
        }
        users.save(new AppUser(username, passwordEncoder.encode(password)));
        return "redirect:/login?registered";
    }
}