package com.example.demo.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.user.dto.LoginRequest;
import com.example.demo.user.dto.UserDto;
import com.example.demo.user.entity.StdUser;
import com.example.demo.user.repository.UserRepository;
import com.example.demo.user.service.LoginService;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class LoginController {
    
    @Autowired
    private LoginService loginService;
    // @GetMapping("/api/helloworld")
    // public String helloWorldGet(){
    //     try
    //     {
    //         StdUser user = new StdUser();
    //         user.setId("testid");
    //         user.setPassword("testpw");
    //         user.setName("testname");
    //         user.setEmail("testemail");
    //         user.setPersonalNumber("testpersonalnumber");
    //         log.info(user.toString());
    //         userRepository.save(user);
    //     }
    //     catch(Exception e){
    //         log.info(e.getMessage());
    //     }
    //     return "Hello Hi!";
    // }

    @PostMapping("/api/login")
    public UserDto login(@Valid @RequestBody LoginRequest loginRequest,
                            BindingResult bindingResult)
    {
        UserDto tt = loginService.Login(loginRequest);
        return tt;        
    }

    // @PatchMapping("/api/hellopatch/{id}")
    // public test helloPatch(@PathVariable Long id, 
    //                         @Valid @RequestBody test dddd,
    //                         BindingResult bindingResult)
    // {
    //     dddd.setId(dddd.getId() + id);
    //     return dddd;
    // }
}
