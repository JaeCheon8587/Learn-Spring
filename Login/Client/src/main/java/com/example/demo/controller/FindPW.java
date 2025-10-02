package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import org.springframework.ui.Model;
import com.example.demo.dto.*;
import jakarta.validation.Valid;

@Controller
public class FindPW {
    @PostMapping("/Find/PW")
    public String FindUserAccountPW(@Valid @ModelAttribute FindPWRequest pwRequest,
                                    BindingResult bindingResult,
                                    Model model){

        return "";
    }
}
