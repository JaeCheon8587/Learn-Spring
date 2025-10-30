package com.example.demo.user.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.security.JwtTokenProvider;
import com.example.demo.user.dto.LoginReply;
import com.example.demo.user.dto.LoginRequest;
import com.example.demo.user.dto.UserDto;
import com.example.demo.user.entity.StdUser;
import com.example.demo.user.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * 사용자 로그인 처리 서비스
 *
 * 주요 기능:
 * - 사용자 인증 (ID/비밀번호 검증)
 * - JWT 토큰 생성
 * - 로그인 성공/실패 응답 생성
 */
@Service
@Slf4j
public class LoginService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    /**
     * 사용자 로그인 처리
     *
     * @param loginRequest 로그인 요청 정보 (ID, 비밀번호)
     * @return 로그인 결과 (성공 시 JWT 토큰 포함)
     */
    public LoginReply Login(LoginRequest loginRequest) {
        log.info("Login attempt for user: {}", loginRequest.getId());

        try {
            StdUser user = findUserById(loginRequest.getId());
            validatePassword(loginRequest.getPw(), user.getPassword());
            return createSuccessReply(user);

        } catch (RuntimeException ex) {
            log.error("Login failed for user {}: {}", loginRequest.getId(), ex.getMessage());
            return new LoginReply(false, ex.getMessage(), null);
        }
    }

    private StdUser findUserById(String userId) {
        return userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("Login failed. User not found."));
    }

    private void validatePassword(String rawPassword, String encodedPassword) {
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new RuntimeException("Login failed. Incorrect password.");
        }
    }

    private LoginReply createSuccessReply(StdUser user) {
        UserDto userDto = user.toDto();
        String token = jwtTokenProvider.generateToken(user.getId());

        log.info("Login success for user: {}", user.getId());

        LoginReply reply = new LoginReply(true, "Login success", userDto);
        reply.setToken(token);
        return reply;
    }
}
