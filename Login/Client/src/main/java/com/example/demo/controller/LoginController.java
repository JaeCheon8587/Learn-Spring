package com.example.demo.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.client.RestTemplate;

import com.example.demo.Service.LoginService;
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

	@PostMapping("/Login/UserAccount")
	public String tryLogin(@Valid @ModelAttribute LoginRequest userAccount,
	                        BindingResult bindingResult,
	                        Model model)
	{
		if(bindingResult.hasErrors()){
			return "/Login";
		}

		try {
			loginService.loginToServer(userAccount);
			// model.addAttribute("result", response);
			// model.addAttribute("username", userAccount.getName());

			return "LoginSuccess";

		} catch (Exception e) {
			log.error("REST API call failed", e);
			model.addAttribute("error", "서버와의 통신에 실패했습니다: " + e.getMessage());
			return "Login";
		}
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
