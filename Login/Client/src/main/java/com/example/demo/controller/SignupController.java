package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.demo.Service.SignupService;
import com.example.demo.dto.SignupReply;
import com.example.demo.dto.SignupRequest;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
public class SignupController {
    @Autowired
    private SignupService signupService;
    
    private void SetUserAccountToModel(Model model, SignupRequest signupRequest){
        model.addAttribute("id", signupRequest.getId());
        model.addAttribute("password", signupRequest.getPw());
        model.addAttribute("name", signupRequest.getName());
        model.addAttribute("email", signupRequest.getEmail());
        model.addAttribute("personalNumber", signupRequest.getPersonalNumber());
    }

    private void SetPopupToModel(Model model, String type, String message){
        model.addAttribute("popupType", type);
        model.addAttribute("popupMessage", message);
    }

    @PostMapping("/Signup/UserAccount")
    public String SignupUserAccount(@Valid @ModelAttribute SignupRequest signupRequest,
                                    BindingResult bindingResult,
                                    Model model)
    {
        //1. RestAPI를 통해 계정 정보 전송
        //2. 결과 렌더링
        //2-1. 성공 페이지
        //2-2. 실패 페이지
        if(bindingResult.hasErrors()){
            return "Signup";
        }
        
        try{
            SignupReply reply = signupService.signupToServer(signupRequest);
            if(!reply.getRet()){
                log.error("회원 가입을 할 수 없습니다. 이유 : {}", reply.getMsg());

                SetPopupToModel(model, "Warning", "회원 가입을 할 수 없습니다. 이유 : " + reply.getMsg());
                SetUserAccountToModel(model, signupRequest);
            }
            else{
                log.info("회원 가입이 완료되었습니다.");

                SetPopupToModel(model, "Success", "회원 가입이 완료되었습니다.");
                SetUserAccountToModel(model, signupRequest);
            }
            
            return "Signup";
        } 
        catch(RuntimeException e){
            log.error("회원 가입 중 오류가 발생하였습니다. 이유 : {}", e.getMessage());
            SetPopupToModel(model, "Error", "회원 가입 중 오류가 발생하였습니다. 이유 : " + e.getMessage());
            return "Signup";
        }
    }
}
