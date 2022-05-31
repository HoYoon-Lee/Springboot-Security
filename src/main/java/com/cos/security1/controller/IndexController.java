package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@RequiredArgsConstructor
@RequestMapping("")
@Controller
public class IndexController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    @GetMapping
    public String index(){
        return "index";
    }

    @GetMapping("loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("join")
    public String join(User user){
        user.setRole("ROLE_USER");
        user.setPassword(encoder.encode(user.getPassword()));
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @GetMapping("user")
    public String user(){
        return "user";
    }

    @GetMapping("admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("manager")
    public String manager(){
        return "manager";
    }

//    @Secured("ROLE_ADMIN")
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("data")
    public @ResponseBody String data(){
        return "data";
    }
}
