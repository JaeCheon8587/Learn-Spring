package com.example.demo.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class FindIDRequest {

	@NotBlank(message = "이름을 입력해주세요")
	private String name;

	@NotBlank(message = "주민번호를 입력해주세요.")
	private String personalNumber;
}
