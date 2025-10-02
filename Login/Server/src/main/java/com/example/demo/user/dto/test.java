package com.example.demo.user.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class test {
    @NotBlank(message = "id를 입력하세요.")
    private String id;
    @NotBlank(message = "pw를 입력하세요.")
    private String pw;
}
