package com.example.demo.user.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.user.dto.LoginRequest;
import com.example.demo.user.dto.UserDto;
import com.example.demo.user.entity.StdUser;
import com.example.demo.user.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class LoginService {
    
    @Autowired
    private UserRepository userRepository;

    public UserDto Login(LoginRequest loginrequest){
        Optional<StdUser> entity = userRepository.findByIdAndPassword(loginrequest.getId(), loginrequest.getPw());
        
        if(!entity.isPresent()){
            log.info("Login failed");
            return null;
        }

        log.info("Login success. Login Information : {}", entity.get().toString());
        return entity.get().toDto();
    }
}
