package com.example.demo.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.UserDto;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class LoginService {
    @Autowired
    private RestTemplate restTemplate;

	@Value("${server.api.url}")
	private String serverApiUrl;

    public String loginToServer(LoginRequest useraccount)
    {
        String url = serverApiUrl + "/api/login";
        log.info("Calling REST API: {}", url);

        UserDto replyUserInfo = restTemplate.postForObject(url, useraccount, UserDto.class);

		log.info("API Response: {}", replyUserInfo.toString());
		return "LoginSuccess";
    }
}
