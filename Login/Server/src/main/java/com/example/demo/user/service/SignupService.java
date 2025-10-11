package com.example.demo.user.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.user.dto.SignupReply;
import com.example.demo.user.dto.SignupRequest;
import com.example.demo.user.entity.StdUser;
import com.example.demo.user.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class SignupService {
    @Autowired
    private UserRepository userRepository;
    
    public SignupReply signup(SignupRequest signupRequest)
    {
        SignupReply signupReply = null;

        Optional<StdUser> result = userRepository.findById(signupRequest.getId());
        
        if(!result.isEmpty())
        {
            StdUser stdUser = result.get();        
            if(stdUser != null){
                log.info("User already exists. Signup Information : {}", stdUser.toString());
                signupReply = new SignupReply(false, "User already exists.", stdUser.toDto());
            }
            else{
                signupReply = new SignupReply(false, "Unknown Error", null);
            }

            return signupReply;
        }
        
        StdUser savedUser = userRepository.save(signupRequest.toStdUser());
        signupReply = new SignupReply(true, "Signup Success", savedUser.toDto());

        return signupReply;
    }
}
