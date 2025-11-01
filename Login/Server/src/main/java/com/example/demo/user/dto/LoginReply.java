package com.example.demo.user.dto;

import lombok.*;

@Getter 
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LoginReply {
    private Boolean ret;
    private String msg;
    private UserDto userAccount;
    private String token;

    public LoginReply(Boolean ret, String msg, UserDto userAccount) {
        this.ret = ret;
        this.msg = msg;
        this.userAccount = userAccount;
        this.token = null;
    }
}
