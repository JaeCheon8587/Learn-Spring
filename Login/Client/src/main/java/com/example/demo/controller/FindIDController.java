package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.demo.dto.FindIDRequest;

import jakarta.validation.Valid;

@Controller
public class FindIDController {

	@PostMapping("/Find/ID")
	public String findUserAccountID(
			@Valid @ModelAttribute FindIDRequest request,
			BindingResult bindingResult,
			Model model) {

		if (bindingResult.hasErrors()) {
			return "FindID";
		}

		//RestAPI를 통해 ID 찾기 요청
		//결과를 model에 담아서 반환
		return "";
	}
}
