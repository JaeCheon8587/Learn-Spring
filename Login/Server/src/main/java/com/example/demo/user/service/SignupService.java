package com.example.demo.user.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
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
    @Autowired
    private PasswordEncoder passwordEncoder;

    private String GetEncodedPassword(String rawPassword){
        return passwordEncoder.encode(rawPassword);
    }
    
    private void ValidateExistUser(String id){
         Optional<StdUser> user = userRepository.findById(id);
         if(!user.isEmpty()){
            throw new RuntimeException("Signup failed. User already exists.");
         }
    }
    private StdUser EncodeStdUserPw(SignupRequest signupRequest){
            signupRequest.setPw(GetEncodedPassword(signupRequest.getPw()));
            return signupRequest.toStdUser();
    }
    private StdUser SaveUser(SignupRequest signupRequest) throws RuntimeException {
        StdUser stdUser = EncodeStdUserPw(signupRequest);
        return userRepository.save(stdUser);
    }

    public SignupReply signup(SignupRequest signupRequest)
    {
        try{
            ValidateExistUser(signupRequest.getId());

            StdUser savedUser = SaveUser(signupRequest);
            return new SignupReply(true, "Signup Success", savedUser.toDto());   
        }
        catch(RuntimeException ex){
            log.error("Signup Service Error : {}", ex.getMessage());
            return new SignupReply(false, ex.getMessage(), null);
        }        
    }
}
