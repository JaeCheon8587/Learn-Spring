package com.example.demo.controller;


import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.demo.Service.LoginService;
import com.example.demo.dto.LoginReply;
import com.example.demo.dto.LoginRequest;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Controller
public class LoginController {

	@Autowired
	private LoginService loginService;

	@GetMapping("/Login")
    public String accessLogin(){
        return "Login";
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
    
    private void SetPopupToModel(LoginReply reply, Model model){
        if(!reply.getRet()){
            model.addAttribute("Popup", "로그인 실패: " + reply.getMsg());
        }

		model.addAttribute("Popup", "로그인 성공");
    }

	@PostMapping("/Login/UserAccount")
	public String tryLogin(@Valid @ModelAttribute LoginRequest userAccount,
	                        BindingResult bindingResult,
	                        Model model)
	{
        if(bindingResult.hasErrors()){
            model.addAttribute("Popup", "올바른 정보를 입력해주세요. ");
            return "Login";
        }

		try {
			LoginReply reply = loginService.loginToServer(userAccount);
            SetPopupToModel(reply, model);

			return "Login";

		} 
		catch (RuntimeException e) {
			model.addAttribute("Popup", "로그인 실패: " + e.getMessage());
			return "Login";
		}
	}
}
