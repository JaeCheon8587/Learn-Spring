package com.example.demo.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.user.dto.SignupReply;
import com.example.demo.user.dto.SignupRequest;
import com.example.demo.user.service.SignupService;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class SignupController {
    @Autowired
    private SignupService signupService;

    @PostMapping("/api/signup")
    public SignupReply signup(@Valid @RequestBody SignupRequest signupRequest,
                            BindingResult bindingResult)
    {
        log.info("Signup Request : {}", signupRequest.toString());
        if(bindingResult.hasErrors()){
            for(var error : bindingResult.getFieldErrors()){
                System.out.println(error.getField() + " : " + error.getDefaultMessage());
            }
        }

        var reply = signupService.signup(signupRequest);       
        return reply;
    }
}
