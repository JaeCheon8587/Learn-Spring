package com.example.demo.user.dto;


import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    @NotBlank(message = "아이디를 입력하세요.")
    private String id;
    @NotBlank(message = "패스워드를 입력하세요.")
    private String pw;
    
}

