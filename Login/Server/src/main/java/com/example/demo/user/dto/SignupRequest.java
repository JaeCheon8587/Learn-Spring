package com.example.demo.user.dto;

import com.example.demo.user.entity.StdUser;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class SignupRequest {
    @NotBlank(message = "아이디를 입력하세요.")
    private String id;
    @NotBlank(message = "패스워드를 입력하세요.")
    private String pw;
    @NotBlank(message = "이름을 입력하세요.")
    private String name;
    @NotBlank(message = "이메일을 입력하세요.")
    private String email;
    @NotBlank(message = "주민번호를 입력하세요.")
    private String personalNumber;
    public StdUser toStdUser() {
        return new StdUser(null, id, pw, name, email, personalNumber);
    }
}
