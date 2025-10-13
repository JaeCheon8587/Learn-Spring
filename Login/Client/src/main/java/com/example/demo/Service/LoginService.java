package com.example.demo.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.client.RestTemplate;

import com.example.demo.dto.LoginReply;
import com.example.demo.dto.LoginRequest;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class LoginService {
    @Autowired
    private RestTemplate restTemplate;

	@Value("${server.api.url}")
	private String serverApiUrl;

    public LoginReply loginToServer(LoginRequest useraccount) throws RuntimeException
    {
        String url = serverApiUrl + "/api/login";
        log.info("Calling REST API: {}", url);

        LoginReply reply = restTemplate.postForObject(url, useraccount, LoginReply.class);
        if(reply == null){
            log.error("Login Failed: No response from server");
            throw new RuntimeException("No response from server");
        }
        
        if(!reply.getRet()){
            log.error("Login Failed: {}", reply.getMsg());
            throw new RuntimeException("Login Failed: " + reply.getMsg());
        }
        
        log.info("Login Success");
        return reply;
    }
}
