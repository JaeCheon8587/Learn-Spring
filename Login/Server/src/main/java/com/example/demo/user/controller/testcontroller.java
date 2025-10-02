package com.example.demo.user.controller;

import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.user.dto.test;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class testcontroller {
        
    @GetMapping("/api/helloworld")
    public String helloWorldGet(){
        return "Hello Hi!";
    }

    @PostMapping("/api/hellopost")
    public test helloPost(@Valid @RequestBody test ddd,
                            BindingResult bindingResult)
    {
        if(bindingResult.hasErrors()){
            log.info("Post Error 발생.");
            for(FieldError a : bindingResult.getFieldErrors()){
                log.info(a.getDefaultMessage());
            }
        }
        
        ddd.setId(ddd.getId() + "1");
        ddd.setPw(ddd.getPw()+"2");
        return ddd;
    }
    @PatchMapping("/api/hellopatch/{id}")
    public test helloPatch(@PathVariable Long id, 
                            @Valid @RequestBody test dddd,
                            BindingResult bindingResult)
    {
        dddd.setId(dddd.getId() + id);
        return dddd;
    }
}
