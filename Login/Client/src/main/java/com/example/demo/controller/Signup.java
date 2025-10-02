package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.demo.dto.SignupRequest;

import jakarta.validation.Valid;


@Controller
public class Signup {

    @PostMapping("/Signup/UserAccount")
    public String SignupUserAccount(@Valid @ModelAttribute SignupRequest signupRequest,
                                    BindingResult bindingresult,
                                    Model model)
    {
        //1. RestAPI를 통해 계정 정보 전송
        //2. 결과 렌더링
        //2-1. 성공 페이지
        //2-2. 실패 페이지
        if(bindingresult.hasErrors()){
            return "Signup";
        }
        
        return "";
    }
}
