package com.example.demo.controller;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.demo.dto.LoginRequest;

import jakarta.validation.Valid;


@Controller
public class Login {

    @GetMapping("/Login")
    public String accessLogin(){
        return "Login";
    }

    @PostMapping("/Login/UserAccount")
    public String tryLogin(@Valid @ModelAttribute LoginRequest useraccount,
                            BindingResult bindingResult,
                            Model model)
    {
        if(bindingResult.hasErrors()){
            return "/Login";
        }
        return "";
    }
    @GetMapping("/Signup")
    public String signUpUser(){
        return "Signup";
    }
    @GetMapping("/FindID")
    public String find0UserID(){
        return "FindID";
    }
    @GetMapping("/FindPW")
    public String findUserPW(){
        return "FindPW";
    }
}
