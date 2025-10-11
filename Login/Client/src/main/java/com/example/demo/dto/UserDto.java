package com.example.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Data
@Getter 
@Setter 
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class UserDto {
    private Long seq;
    private String id;
    private String password;
    private String name;
    private String email;
    private String personalNumber;

}
