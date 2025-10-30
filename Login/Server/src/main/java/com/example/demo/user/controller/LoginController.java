package com.example.demo.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.user.dto.LoginReply;
import com.example.demo.user.dto.LoginRequest;
import com.example.demo.user.dto.UserDto;
import com.example.demo.user.service.LoginService;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class LoginController {
    
    @Autowired
    private LoginService loginService;

    @PostMapping("/api/login")
    public LoginReply login(@Valid @RequestBody LoginRequest loginRequest,
                            BindingResult bindingResult)
    {
        try{
            LoginReply loginReply = loginService.Login(loginRequest);
            return loginReply;        
        }
        catch(RuntimeException ex){
            log.error("Login failed. Error Information : {}", ex.getMessage());
            return new LoginReply(false, ex.getMessage(), null);
        }        
    }
}
