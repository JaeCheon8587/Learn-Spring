package com.example.demo.user.controller;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.example.demo.user.dto.SignupRequest;
import com.example.demo.user.service.SignupService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SpringBootTest
public class SignupServiceTest {
    @Autowired
    private SignupService signupService;

    private SignupRequest createSignupRequest(String id, String pw, String name, String email, String personalNumber) {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setId(id);
        signupRequest.setPw(pw);
        signupRequest.setName(name);
        signupRequest.setEmail(email);
        signupRequest.setPersonalNumber(personalNumber);
        return signupRequest;
    }
    @Test
    void testSignup() {
        SignupRequest signupRequest = createSignupRequest("testuser", 
                                                            "testpassword", 
                                                            "Test User", 
                                                            "test@example.com", 
                                                            "123456-1234567");
        var reply = signupService.signup(signupRequest);
        assertTrue(reply.getRet());
    }
}
