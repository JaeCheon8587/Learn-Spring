package com.example.demo.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.example.demo.dto.SignupReply;
import com.example.demo.dto.SignupRequest;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class SignupService {
    @Autowired
    private RestTemplate restTemplate = new RestTemplate();

	@Value("${server.api.url}")
	private String serverApiUrl;

    public SignupReply signupToServer(SignupRequest signupRequest) throws RuntimeException {
        String url = serverApiUrl + "/api/signup";

        SignupReply dto = restTemplate.postForObject(url, signupRequest, SignupReply.class);
        if(dto == null){
            log.error("Sign Up Failed: No response from server");
            throw new RuntimeException("No response from server");
        }
        if(!dto.getRet()){
            log.error("Sign Up Failed: {}", dto.getMsg());
            return dto;
        }
        
        log.info("Sign Up User: {}", dto.toString());
        return dto;
    }
}
