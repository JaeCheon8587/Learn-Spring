# Spring Security와 JWT 완벽 가이드

> **학습 목표**: Spring Security와 JWT를 이용한 안전한 인증 시스템 구축
> **대상**: Spring Boot 초급자, Spring Security 처음 다루는 개발자
> **프로젝트 컨텍스트**: 클라이언트-서버 분리 아키텍처 (Client:8081 ↔ Server:8080)

---

## 목차
1. [Spring Security 기초 개념](#1-spring-security-기초-개념)
2. [JWT (JSON Web Token) 이해하기](#2-jwt-json-web-token-이해하기)
3. [클라이언트-서버 인증 흐름](#3-클라이언트-서버-인증-흐름)
4. [단계별 구현 가이드](#4-단계별-구현-가이드)
5. [보안 Best Practices](#5-보안-best-practices)
6. [트러블슈팅 가이드](#6-트러블슈팅-가이드)

---

## 1. Spring Security 기초 개념

### 1.1 Spring Security란?

Spring Security는 Spring 기반 애플리케이션의 **인증(Authentication)**과 **인가(Authorization)**를 담당하는 보안 프레임워크입니다.

**핵심 개념 비교**:

| 개념 | 의미 | 비유 | 예시 |
|------|------|------|------|
| **Authentication** (인증) | 사용자가 누구인지 확인 | 신분증 확인 | 로그인 시 ID/PW 검증 |
| **Authorization** (인가) | 사용자가 무엇을 할 수 있는지 결정 | 출입 권한 확인 | 관리자만 회원 삭제 가능 |

### 1.2 Spring Security 아키텍처

Spring Security의 핵심은 **Filter Chain**입니다. HTTP 요청이 들어오면 여러 필터를 거쳐 최종적으로 컨트롤러에 도달합니다.

```
[HTTP 요청]
    ↓
[SecurityContextPersistenceFilter]  ← 보안 컨텍스트 로드
    ↓
[UsernamePasswordAuthenticationFilter]  ← 로그인 처리
    ↓
[ExceptionTranslationFilter]  ← 보안 예외 처리
    ↓
[FilterSecurityInterceptor]  ← 권한 검사
    ↓
[Controller]  ← 최종 목적지
```

**실제 동작 예시**:
```
1. 사용자가 /api/login으로 POST 요청
2. UsernamePasswordAuthenticationFilter가 요청 가로챔
3. AuthenticationManager에게 인증 위임
4. UserDetailsService가 DB에서 사용자 정보 조회
5. 비밀번호 검증 (BCrypt 사용)
6. 인증 성공 → SecurityContext에 인증 정보 저장
7. JWT 토큰 생성 및 응답
```

### 1.3 주요 컴포넌트

#### SecurityFilterChain
Spring Security의 필터 체인을 구성하는 핵심 Bean입니다.

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/login", "/api/signup").permitAll()  // 인증 불필요
            .anyRequest().authenticated()  // 나머지는 인증 필요
        )
        .csrf(csrf -> csrf.disable())  // REST API는 CSRF 불필요
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // JWT 사용 시
        );

    return http.build();
}
```

#### UserDetailsService
사용자 정보를 데이터베이스에서 조회하는 인터페이스입니다.

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        StdUser user = userRepository.findById(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return User.builder()
            .username(user.getId())
            .password(user.getPassword())  // BCrypt 해시된 비밀번호
            .roles("USER")  // 권한 설정
            .build();
    }
}
```

#### PasswordEncoder
비밀번호를 안전하게 저장하기 위한 인코더입니다. **절대 평문 저장 금지!**

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();  // 업계 표준
}

// 사용 예시
String rawPassword = "userPassword123";
String encodedPassword = passwordEncoder.encode(rawPassword);
// 결과: $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy

// 검증
boolean matches = passwordEncoder.matches("userPassword123", encodedPassword);  // true
```

### 1.4 Filter Chain 동작 흐름 다이어그램

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP Request                             │
│                    (POST /api/login)                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              SecurityContextPersistenceFilter                   │
│  • SecurityContext 로드 (이전 인증 정보 복원)                    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         UsernamePasswordAuthenticationFilter                    │
│  • /api/login 요청 감지                                          │
│  • username/password 추출                                        │
│  • AuthenticationManager에게 인증 위임                           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  AuthenticationManager                          │
│  • 인증 전략 선택                                                 │
│  • ProviderManager가 적절한 Provider 찾기                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              DaoAuthenticationProvider                          │
│  • UserDetailsService 호출                                       │
│  • 비밀번호 검증 (BCrypt)                                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  UserDetailsService                             │
│  • DB에서 사용자 정보 조회                                        │
│  • UserDetails 객체 반환                                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌─────────────────┐         ┌─────────────────────┐
│  인증 성공       │         │    인증 실패         │
│  • JWT 생성     │         │    • 401 응답        │
│  • 토큰 반환    │         │    • 에러 메시지     │
└─────────────────┘         └─────────────────────┘
```

---

## 2. JWT (JSON Web Token) 이해하기

### 2.1 JWT란?

JWT는 JSON 형식의 정보를 안전하게 전송하기 위한 **토큰 기반 인증 방식**입니다.

**Session vs JWT 비교**:

| 구분 | Session | JWT |
|------|---------|-----|
| **저장 위치** | 서버 메모리/DB | 클라이언트 (브라우저) |
| **확장성** | 서버 부하 증가 (세션 공유 필요) | 서버 부하 적음 (Stateless) |
| **보안** | 서버 관리로 안전 | 토큰 탈취 위험 존재 |
| **만료 처리** | 서버에서 즉시 무효화 가능 | 만료까지 유효 (Refresh 필요) |
| **적합한 경우** | 전통적인 웹 애플리케이션 | REST API, 마이크로서비스 |

**현재 프로젝트에서 JWT를 사용하는 이유**:
- 클라이언트(8081)와 서버(8080)가 분리된 구조
- 서버는 REST API만 제공 (Stateless)
- 클라이언트가 여러 서버와 통신할 수 있는 확장성

### 2.2 JWT 구조

JWT는 `.`으로 구분된 3개 부분으로 구성됩니다:

```
[Header].[Payload].[Signature]
```

**실제 JWT 토큰 예시**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6Iuq5gOuPmeuPmSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAzNjAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

#### Header (헤더)
```json
{
  "alg": "HS256",    // 서명 알고리즘 (HMAC SHA-256)
  "typ": "JWT"       // 토큰 타입
}
```

#### Payload (페이로드) - 실제 데이터
```json
{
  "sub": "user123",           // Subject (사용자 식별자)
  "name": "김동동",            // 사용자 이름
  "iat": 1700000000,          // Issued At (발급 시간)
  "exp": 1700003600           // Expiration (만료 시간, 1시간 후)
}
```

**주의사항**: Payload는 **암호화되지 않습니다**! Base64 디코딩만으로 내용 확인 가능하므로 **민감한 정보(비밀번호, 주민번호 등) 절대 포함 금지**.

#### Signature (서명) - 무결성 검증
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret-key
)
```

서명의 역할:
1. **위변조 방지**: 토큰 내용이 변경되면 서명 불일치
2. **발급자 확인**: secret-key를 가진 서버만 유효한 토큰 생성 가능

### 2.3 JWT 동작 원리

```
[로그인 시]
1. Client → Server: POST /api/login {id: "user123", pw: "password"}
2. Server: 사용자 검증 → JWT 생성 (비밀키로 서명)
3. Server → Client: {token: "eyJhbGc..."}
4. Client: 토큰을 저장 (localStorage, sessionStorage 등)

[API 호출 시]
1. Client → Server: GET /api/users
   Header: Authorization: Bearer eyJhbGc...
2. Server: JWT 검증 (서명 확인, 만료 확인)
3. Server: 검증 성공 → 요청 처리
4. Server → Client: 응답 데이터
```

### 2.4 JWT 사용 시 주의사항

#### 1. 토큰 저장 위치 선택

| 저장소 | 보안성 | XSS 위험 | CSRF 위험 | 권장 여부 |
|--------|--------|----------|-----------|-----------|
| **localStorage** | 낮음 | 높음 | 없음 | ⚠️ 주의 |
| **sessionStorage** | 낮음 | 높음 | 없음 | ⚠️ 주의 |
| **Cookie (HttpOnly)** | 높음 | 없음 | 높음 | ✅ 권장 |
| **Memory (변수)** | 높음 | 없음 | 없음 | ✅ 권장 (새로고침 시 소실) |

**현재 프로젝트 권장사항**:
- **개발 단계**: sessionStorage (간단함)
- **운영 단계**: HttpOnly Cookie + CSRF Token

#### 2. Refresh Token 패턴

Access Token은 짧게(15분~1시간), Refresh Token은 길게(7일~30일) 설정:

```
Access Token 만료 → Refresh Token으로 갱신 요청 → 새 Access Token 발급
```

이유:
- Access Token 탈취 시 피해 최소화
- 장기간 로그인 유지 가능

#### 3. 토큰 만료 처리

```javascript
// Client에서 401 응답 처리 예시
if (response.status === 401) {
    // 1. Refresh Token으로 갱신 시도
    const newToken = await refreshAccessToken();

    if (newToken) {
        // 2. 재시도
        return retryRequest(newToken);
    } else {
        // 3. 로그인 페이지로 리다이렉트
        window.location.href = '/login';
    }
}
```

---

## 3. 클라이언트-서버 인증 흐름

### 3.1 현재 프로젝트 아키텍처

```
┌──────────────────┐                    ┌──────────────────┐
│   Client App     │                    │   Server App     │
│   (Port 8081)    │                    │   (Port 8080)    │
│                  │                    │                  │
│  ┌────────────┐  │                    │  ┌────────────┐  │
│  │ Mustache   │  │                    │  │ REST API   │  │
│  │ Template   │  │                    │  │ Controller │  │
│  └──────┬─────┘  │                    │  └──────┬─────┘  │
│         │        │                    │         │        │
│  ┌──────▼─────┐  │  RestTemplate      │  ┌──────▼─────┐  │
│  │ Controller │  │ ─────────────────► │  │  Service   │  │
│  └──────┬─────┘  │  HTTP Request      │  └──────┬─────┘  │
│         │        │                    │         │        │
│  ┌──────▼─────┐  │                    │  ┌──────▼─────┐  │
│  │  Service   │  │                    │  │ Repository │  │
│  └────────────┘  │                    │  └──────┬─────┘  │
│                  │                    │         │        │
└──────────────────┘                    │  ┌──────▼─────┐  │
                                        │  │  Oracle DB │  │
                                        │  └────────────┘  │
                                        └──────────────────┘
```

### 3.2 로그인 전체 흐름 (Sequence Diagram)

```
사용자       Client          Server          Database
  │            │               │                 │
  │  1. 로그인 폼 제출         │                 │
  ├───────────►│               │                 │
  │            │               │                 │
  │            │  2. POST /api/login            │
  │            ├──────────────►│                 │
  │            │   {id, pw}    │                 │
  │            │               │                 │
  │            │               │  3. SELECT user │
  │            │               ├────────────────►│
  │            │               │                 │
  │            │               │  4. User data   │
  │            │               │◄────────────────┤
  │            │               │                 │
  │            │               │  5. BCrypt 검증  │
  │            │               │  matches(pw)    │
  │            │               │                 │
  │            │  6. JWT 생성   │                 │
  │            │  {token: ...} │                 │
  │            │◄──────────────┤                 │
  │            │               │                 │
  │  7. 토큰 저장 (sessionStorage)              │
  │◄───────────┤               │                 │
  │            │               │                 │
  │  8. 메인 페이지 이동                          │
  │◄───────────┤               │                 │
```

### 3.3 인증이 필요한 API 호출 흐름

```
사용자       Client          Server
  │            │               │
  │  1. "내 정보 보기" 클릭     │
  ├───────────►│               │
  │            │               │
  │            │  2. GET /api/users/me
  │            ├──────────────►│
  │            │  Header:      │
  │            │  Authorization: Bearer eyJhbGc...
  │            │               │
  │            │               │  3. JWT 검증
  │            │               │  • 서명 확인
  │            │               │  • 만료 확인
  │            │               │  • 사용자 추출
  │            │               │
  │            │  4. User data │
  │            │◄──────────────┤
  │            │  {name, ...}  │
  │            │               │
  │  5. 화면 렌더링            │
  │◄───────────┤               │
```

### 3.4 토큰 갱신 (Refresh Token) 흐름

```
Client                          Server
  │                               │
  │  1. API 호출 (Access Token 만료)
  ├──────────────────────────────►│
  │                               │
  │  2. 401 Unauthorized           │
  │◄───────────────────────────────┤
  │  {error: "Token expired"}     │
  │                               │
  │  3. POST /api/refresh          │
  ├──────────────────────────────►│
  │  {refreshToken: "..."}        │
  │                               │
  │                               │  4. Refresh Token 검증
  │                               │
  │  5. New Access Token          │
  │◄───────────────────────────────┤
  │  {accessToken: "new..."}      │
  │                               │
  │  6. 원래 요청 재시도            │
  ├──────────────────────────────►│
  │  Header: Authorization: Bearer new...
  │                               │
  │  7. 성공 응답                  │
  │◄───────────────────────────────┤
```

### 3.5 에러 상황별 처리

| 상태 코드 | 의미 | 원인 | Client 처리 |
|-----------|------|------|-------------|
| **401 Unauthorized** | 인증 실패 | 토큰 없음/만료/유효하지 않음 | Refresh 시도 → 실패 시 로그인 페이지 |
| **403 Forbidden** | 권한 없음 | 인증은 됐지만 해당 리소스 접근 불가 | "권한 없음" 메시지 표시 |
| **500 Internal Server Error** | 서버 오류 | JWT 서명 검증 실패, DB 오류 등 | 일반 에러 메시지 표시 |

---

## 4. 단계별 구현 가이드

### 4.1 사전 준비 (의존성 추가)

**Server 모듈의 `build.gradle`에 추가**:

```gradle
dependencies {
    // 기존 의존성...

    // Spring Security
    implementation 'org.springframework.boot:spring-boot-starter-security'

    // JWT 라이브러리 (jjwt)
    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.12.3'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.12.3'

    // 테스트
    testImplementation 'org.springframework.security:spring-security-test'
}
```

**변경 후 Gradle 새로고침**:
```bash
cd Server
./gradlew clean build
```

---

### 4.2 Step 1: 비밀번호 암호화 (Server)

#### 현재 문제점
```java
// Server/src/main/java/com/example/demo/user/service/SignupService.java
public SignupReply Signup(SignupRequest request) {
    StdUser newUser = new StdUser();
    newUser.setPassword(request.getPw());  // ❌ 평문 저장!
    // ...
}
```

#### 해결: PasswordEncoder 설정

**파일 생성**: `Server/src/main/java/com/example/demo/config/SecurityConfig.java`

```java
package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig {

    /**
     * 비밀번호 암호화를 위한 BCrypt 인코더
     *
     * BCrypt 특징:
     * - Salt 자동 생성 (같은 비밀번호도 매번 다른 해시 생성)
     * - 느린 해싱 속도 (무차별 대입 공격 방어)
     * - 검증: matches() 메서드 사용
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

#### SignupService 수정

```java
package com.example.demo.user.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class SignupService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;  // 추가

    public SignupReply Signup(SignupRequest request) {
        // 중복 체크
        Optional<StdUser> existingUser = userRepository.findById(request.getId());
        if (existingUser.isPresent()) {
            return new SignupReply(false, "이미 존재하는 아이디입니다.", null);
        }

        // 새 사용자 생성
        StdUser newUser = new StdUser();
        newUser.setId(request.getId());

        // ✅ 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(request.getPw());
        newUser.setPassword(encodedPassword);

        newUser.setName(request.getName());
        newUser.setEmail(request.getEmail());
        newUser.setPersonalNumber(request.getPersonalNumber());

        StdUser savedUser = userRepository.save(newUser);

        // DTO 변환
        UserDto userDto = new UserDto(
            savedUser.getSeq(),
            savedUser.getId(),
            null,  // 비밀번호는 응답에 포함하지 않음
            savedUser.getName(),
            savedUser.getEmail(),
            savedUser.getPersonalNumber()
        );

        return new SignupReply(true, "회원가입 성공", userDto);
    }
}
```

#### LoginService 수정

```java
package com.example.demo.user.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class LoginService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;  // 추가

    public LoginReply Login(LoginRequest request) {
        // 사용자 조회
        Optional<StdUser> userOptional = userRepository.findById(request.getId());

        if (userOptional.isEmpty()) {
            return new LoginReply(false, "존재하지 않는 아이디입니다.", null);
        }

        StdUser user = userOptional.get();

        // ✅ BCrypt로 비밀번호 검증
        boolean passwordMatches = passwordEncoder.matches(
            request.getPw(),           // 사용자가 입력한 평문 비밀번호
            user.getPassword()         // DB에 저장된 암호화된 비밀번호
        );

        if (!passwordMatches) {
            return new LoginReply(false, "비밀번호가 일치하지 않습니다.", null);
        }

        // 로그인 성공
        UserDto userDto = new UserDto(
            user.getSeq(),
            user.getId(),
            null,  // 비밀번호는 응답에 포함하지 않음
            user.getName(),
            user.getEmail(),
            user.getPersonalNumber()
        );

        return new LoginReply(true, "로그인 성공", userDto);
    }
}
```

**테스트 방법**:
```bash
# 1. Server 실행
cd Server
./gradlew bootRun

# 2. 회원가입 테스트
curl -X POST http://localhost:8080/api/signup \
  -H "Content-Type: application/json" \
  -d '{
    "id": "testuser",
    "pw": "password123",
    "name": "테스트",
    "email": "test@example.com",
    "personalNumber": "123456-1234567"
  }'

# 3. DB 확인 (비밀번호가 해시값으로 저장되어 있어야 함)
# $2a$10$... 형태의 문자열 확인
```

---

### 4.3 Step 2: JWT 유틸리티 클래스 작성 (Server)

JWT 생성, 검증, 파싱 기능을 담당하는 유틸리티 클래스를 만듭니다.

**파일 생성**: `Server/src/main/java/com/example/demo/security/JwtTokenProvider.java`

```java
package com.example.demo.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JWT 토큰 생성 및 검증을 담당하는 유틸리티 클래스
 *
 * 주요 기능:
 * 1. JWT 생성 (generateToken)
 * 2. JWT 검증 (validateToken)
 * 3. 사용자 ID 추출 (getUserIdFromToken)
 */
@Component
public class JwtTokenProvider {

    // application.properties에서 주입
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;  // 밀리초 단위

    /**
     * SecretKey 생성 (HMAC SHA-256)
     *
     * 보안 요구사항:
     * - 최소 256비트 (32바이트) 길이
     * - 예측 불가능한 랜덤 문자열
     * - 환경변수로 관리 권장
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * JWT 토큰 생성
     *
     * @param userId 사용자 ID (Subject로 사용)
     * @return JWT 토큰 문자열
     */
    public String generateToken(String userId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .setSubject(userId)                    // 사용자 식별자
                .setIssuedAt(now)                      // 발급 시간
                .setExpiration(expiryDate)             // 만료 시간
                .signWith(getSigningKey())             // 서명
                .compact();
    }

    /**
     * JWT 토큰에서 사용자 ID 추출
     *
     * @param token JWT 토큰
     * @return 사용자 ID
     */
    public String getUserIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    /**
     * JWT 토큰 유효성 검증
     *
     * 검증 항목:
     * 1. 서명 유효성 (위변조 확인)
     * 2. 만료 시간 확인
     * 3. 토큰 형식 확인
     *
     * @param token JWT 토큰
     * @return 유효하면 true, 아니면 false
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;

        } catch (MalformedJwtException ex) {
            // 잘못된 JWT 형식
            System.err.println("Invalid JWT token format");
        } catch (ExpiredJwtException ex) {
            // 만료된 토큰
            System.err.println("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            // 지원하지 않는 JWT
            System.err.println("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            // 빈 문자열
            System.err.println("JWT claims string is empty");
        }

        return false;
    }
}
```

**application.properties에 설정 추가**:

```properties
# Server/src/main/resources/application.properties

# JWT 설정
jwt.secret=your-256-bit-secret-key-minimum-32-characters-long-please-change-this
jwt.expiration=3600000
# 3600000ms = 1시간

# 주의: 운영 환경에서는 환경변수로 관리!
# export JWT_SECRET="actual-production-secret-key"
# jwt.secret=${JWT_SECRET}
```

**보안 경고**:
- 실제 운영에서는 `jwt.secret`을 **절대 코드에 포함하지 말 것**!
- 환경변수 또는 AWS Secrets Manager, HashiCorp Vault 등 사용
- Secret Key는 최소 32자 이상, 무작위 문자열

---

### 4.4 Step 3: 로그인 시 JWT 발급 (Server)

LoginService를 수정하여 로그인 성공 시 JWT 토큰을 생성합니다.

#### LoginReply DTO 수정

**파일 위치**: `Server/src/main/java/com/example/demo/user/dto/LoginReply.java`

```java
package com.example.demo.user.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginReply {
    private boolean ret;
    private String msg;
    private UserDto userDto;
    private String token;  // ✅ JWT 토큰 필드 추가

    // 기존 생성자 호환성을 위한 오버로드
    public LoginReply(boolean ret, String msg, UserDto userDto) {
        this.ret = ret;
        this.msg = msg;
        this.userDto = userDto;
        this.token = null;
    }
}
```

#### LoginService 수정

```java
package com.example.demo.user.service;

import com.example.demo.security.JwtTokenProvider;
import com.example.demo.user.dto.LoginReply;
import com.example.demo.user.dto.LoginRequest;
import com.example.demo.user.dto.UserDto;
import com.example.demo.user.entity.StdUser;
import com.example.demo.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class LoginService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;  // ✅ 추가

    public LoginReply Login(LoginRequest request) {
        // 사용자 조회
        Optional<StdUser> userOptional = userRepository.findById(request.getId());

        if (userOptional.isEmpty()) {
            return new LoginReply(false, "존재하지 않는 아이디입니다.", null, null);
        }

        StdUser user = userOptional.get();

        // 비밀번호 검증
        boolean passwordMatches = passwordEncoder.matches(
            request.getPw(),
            user.getPassword()
        );

        if (!passwordMatches) {
            return new LoginReply(false, "비밀번호가 일치하지 않습니다.", null, null);
        }

        // ✅ JWT 토큰 생성
        String token = jwtTokenProvider.generateToken(user.getId());

        // 로그인 성공 응답
        UserDto userDto = new UserDto(
            user.getSeq(),
            user.getId(),
            null,
            user.getName(),
            user.getEmail(),
            user.getPersonalNumber()
        );

        return new LoginReply(true, "로그인 성공", userDto, token);
    }
}
```

**테스트**:
```bash
# 로그인 API 호출
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "id": "testuser",
    "pw": "password123"
  }'

# 응답 예시:
# {
#   "ret": true,
#   "msg": "로그인 성공",
#   "userDto": {...},
#   "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAzNjAwfQ.xxxxx"
# }
```

---

### 4.5 Step 4: JWT 검증 필터 구현 (Server)

모든 요청에서 JWT를 검증하는 Filter를 추가합니다.

**파일 생성**: `Server/src/main/java/com/example/demo/security/JwtAuthenticationFilter.java`

```java
package com.example.demo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

/**
 * JWT 인증 필터
 *
 * 모든 HTTP 요청에서 JWT 토큰을 검증하고
 * 유효한 경우 SecurityContext에 인증 정보 저장
 *
 * 동작 순서:
 * 1. Authorization 헤더에서 토큰 추출
 * 2. 토큰 유효성 검증
 * 3. 사용자 ID 추출
 * 4. SecurityContext에 인증 정보 설정
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            // 1. Request에서 JWT 토큰 추출
            String jwt = getJwtFromRequest(request);

            // 2. 토큰 유효성 검증 및 사용자 ID 추출
            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
                String userId = jwtTokenProvider.getUserIdFromToken(jwt);

                // 3. 인증 객체 생성
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userId,           // principal (사용자 식별자)
                                null,            // credentials (비밀번호, JWT에서는 불필요)
                                new ArrayList<>() // authorities (권한 목록)
                        );

                authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // 4. SecurityContext에 인증 정보 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }

        // 5. 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }

    /**
     * Request Header에서 JWT 토큰 추출
     *
     * Header 형식: Authorization: Bearer <token>
     *
     * @param request HTTP 요청
     * @return JWT 토큰 문자열 (Bearer 제외)
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        // "Bearer " 접두사 제거
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);  // "Bearer " 이후 문자열
        }

        return null;
    }
}
```

---

### 4.6 Step 5: Spring Security 설정 (Server)

SecurityFilterChain을 구성하여 JWT 필터를 적용하고 엔드포인트별 접근 권한을 설정합니다.

**파일 수정**: `Server/src/main/java/com/example/demo/config/SecurityConfig.java`

```java
package com.example.demo.config;

import com.example.demo.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security 설정 클래스
 *
 * 주요 설정:
 * 1. 비밀번호 암호화 (BCrypt)
 * 2. JWT 필터 등록
 * 3. 엔드포인트별 접근 권한
 * 4. CSRF 비활성화 (REST API)
 * 5. Stateless 세션 정책
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CSRF 비활성화 (REST API는 CSRF 토큰 불필요)
            .csrf(csrf -> csrf.disable())

            // 세션 사용하지 않음 (JWT 기반 Stateless)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // 엔드포인트별 접근 권한 설정
            .authorizeHttpRequests(auth -> auth
                // 인증 없이 접근 가능한 엔드포인트
                .requestMatchers(
                    "/api/login",
                    "/api/signup"
                ).permitAll()

                // 나머지 모든 요청은 인증 필요
                .anyRequest().authenticated()
            )

            // JWT 필터 추가 (UsernamePasswordAuthenticationFilter 이전에 실행)
            .addFilterBefore(
                jwtAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }
}
```

**설정 설명**:

| 설정 | 설명 | 이유 |
|------|------|------|
| `csrf.disable()` | CSRF 보호 비활성화 | REST API는 쿠키 기반 인증을 사용하지 않으므로 CSRF 공격 대상이 아님 |
| `sessionCreationPolicy(STATELESS)` | 세션 생성 안 함 | JWT는 서버에 상태를 저장하지 않음 (Stateless) |
| `permitAll()` | 인증 불필요 | 로그인/회원가입은 인증 전에 접근해야 함 |
| `authenticated()` | 인증 필요 | 나머지 API는 JWT 토큰이 있어야만 접근 가능 |
| `addFilterBefore()` | JWT 필터 등록 | 모든 요청에서 JWT 검증 |

---

### 4.7 Step 6: 인증이 필요한 API 추가 (Server)

JWT 인증이 필요한 테스트 엔드포인트를 추가합니다.

**파일 생성**: `Server/src/main/java/com/example/demo/user/controller/UserController.java`

```java
package com.example.demo.user.controller;

import com.example.demo.user.dto.UserDto;
import com.example.demo.user.entity.StdUser;
import com.example.demo.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * 인증이 필요한 사용자 API
 *
 * JWT 토큰이 있어야만 접근 가능
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    /**
     * 현재 로그인한 사용자 정보 조회
     *
     * JWT에서 사용자 ID를 추출하여 DB 조회
     *
     * @return 사용자 정보
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        // SecurityContext에서 인증 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body("인증되지 않은 사용자입니다.");
        }

        // JWT에서 추출한 사용자 ID
        String userId = (String) authentication.getPrincipal();

        // DB에서 사용자 정보 조회
        Optional<StdUser> userOptional = userRepository.findById(userId);

        if (userOptional.isEmpty()) {
            return ResponseEntity.status(404).body("사용자를 찾을 수 없습니다.");
        }

        StdUser user = userOptional.get();

        // DTO 변환 (비밀번호 제외)
        UserDto userDto = new UserDto(
            user.getSeq(),
            user.getId(),
            null,  // 비밀번호는 응답에 포함하지 않음
            user.getName(),
            user.getEmail(),
            user.getPersonalNumber()
        );

        return ResponseEntity.ok(userDto);
    }
}
```

**테스트**:
```bash
# 1. 로그인하여 토큰 받기
TOKEN=$(curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"id":"testuser","pw":"password123"}' \
  | jq -r '.token')

echo "Token: $TOKEN"

# 2. 인증이 필요한 API 호출
curl -X GET http://localhost:8080/api/users/me \
  -H "Authorization: Bearer $TOKEN"

# 성공 응답:
# {
#   "seq": 1,
#   "id": "testuser",
#   "name": "테스트",
#   "email": "test@example.com",
#   "personalNumber": "123456-1234567"
# }

# 3. 토큰 없이 호출 (실패)
curl -X GET http://localhost:8080/api/users/me

# 응답: 401 Unauthorized
```

---

### 4.8 Step 7: Client에서 JWT 저장 및 전송

#### Client LoginService 수정

**파일 수정**: `Client/src/main/java/com/example/demo/Service/LoginService.java`

```java
package com.example.demo.Service;

import com.example.demo.dto.LoginReply;
import com.example.demo.dto.LoginRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class LoginService {

    @Autowired
    private RestTemplate restTemplate;

    @Value("${server.api.url}")
    private String serverApiUrl;

    public LoginReply loginToServer(LoginRequest request) {
        String url = serverApiUrl + "/api/login";

        try {
            ResponseEntity<LoginReply> response = restTemplate.postForEntity(
                url,
                request,
                LoginReply.class
            );

            LoginReply reply = response.getBody();

            if (reply == null) {
                throw new RuntimeException("Server response is null");
            }

            // ✅ JWT 토큰은 Controller에서 세션/쿠키에 저장
            return reply;

        } catch (Exception e) {
            throw new RuntimeException("Login failed: " + e.getMessage());
        }
    }
}
```

#### Client LoginController 수정

**파일 수정**: `Client/src/main/java/com/example/demo/controller/LoginController.java`

```java
package com.example.demo.controller;

import com.example.demo.Service.LoginService;
import com.example.demo.dto.LoginReply;
import com.example.demo.dto.LoginRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/Login")
public class LoginController {

    @Autowired
    private LoginService loginService;

    @GetMapping
    public String showLoginPage(Model model) {
        model.addAttribute("loginRequest", new LoginRequest());
        return "Login";
    }

    @PostMapping("/UserAccount")
    public String login(
            @Valid @ModelAttribute LoginRequest loginRequest,
            BindingResult bindingResult,
            Model model,
            HttpSession session  // ✅ 세션 추가
    ) {
        // 유효성 검사 실패
        if (bindingResult.hasErrors()) {
            return "Login";
        }

        try {
            // 서버에 로그인 요청
            LoginReply reply = loginService.loginToServer(loginRequest);

            if (reply.isRet()) {
                // ✅ 로그인 성공: JWT 토큰을 세션에 저장
                session.setAttribute("jwtToken", reply.getToken());
                session.setAttribute("userId", reply.getUserDto().getId());
                session.setAttribute("userName", reply.getUserDto().getName());

                // 메인 페이지로 리다이렉트 (추후 구현)
                return "redirect:/main";
            } else {
                // 로그인 실패
                model.addAttribute("errorMessage", reply.getMsg());
                return "Login";
            }

        } catch (Exception e) {
            model.addAttribute("errorMessage", "서버 오류: " + e.getMessage());
            return "Login";
        }
    }
}
```

#### RestTemplate Interceptor 추가 (자동 토큰 주입)

**파일 생성**: `Client/src/main/java/com/example/demo/config/JwtInterceptor.java`

```java
package com.example.demo.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;

/**
 * RestTemplate 요청에 JWT 토큰을 자동으로 추가하는 Interceptor
 *
 * 세션에 저장된 JWT 토큰을 모든 API 요청의 Authorization 헤더에 추가
 */
@Component
public class JwtInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(
            HttpRequest request,
            byte[] body,
            ClientHttpRequestExecution execution
    ) throws IOException {

        // 현재 HTTP 세션 가져오기
        ServletRequestAttributes attributes =
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        if (attributes != null) {
            HttpServletRequest servletRequest = attributes.getRequest();
            HttpSession session = servletRequest.getSession(false);

            if (session != null) {
                String jwtToken = (String) session.getAttribute("jwtToken");

                // JWT 토큰이 있으면 Authorization 헤더에 추가
                if (jwtToken != null && !jwtToken.isEmpty()) {
                    request.getHeaders().add("Authorization", "Bearer " + jwtToken);
                }
            }
        }

        // 요청 실행
        return execution.execute(request, body);
    }
}
```

#### RestTemplateConfig 수정

**파일 수정**: `Client/src/main/java/com/example/demo/config/RestTemplateConfig.java`

```java
package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;

@Configuration
public class RestTemplateConfig {

    @Autowired
    private JwtInterceptor jwtInterceptor;  // ✅ 추가

    @Bean
    public RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate();

        // ✅ JWT Interceptor 등록
        restTemplate.setInterceptors(Collections.singletonList(jwtInterceptor));

        return restTemplate;
    }
}
```

#### Login.mustache 수정 (에러 메시지 표시)

**파일 수정**: `Client/src/main/resources/templates/Login.mustache`

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>로그인</title>
    <style>
        .error { color: red; }
        .container { max-width: 400px; margin: 50px auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>로그인</h1>

        {{#errorMessage}}
        <div class="error">{{errorMessage}}</div>
        {{/errorMessage}}

        <form action="/Login/UserAccount" method="post">
            <div>
                <label>아이디:</label>
                <input type="text" name="id" required>
            </div>

            <div>
                <label>비밀번호:</label>
                <input type="password" name="pw" required>
            </div>

            <button type="submit">로그인</button>
        </form>

        <p>
            <a href="/Signup">회원가입</a>
        </p>
    </div>
</body>
</html>
```

---

### 4.9 Step 8: 메인 페이지 구현 (Client)

로그인 성공 후 이동할 메인 페이지를 만듭니다.

**파일 생성**: `Client/src/main/java/com/example/demo/controller/MainController.java`

```java
package com.example.demo.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {

    @GetMapping("/main")
    public String showMainPage(HttpSession session, Model model) {
        // 세션에서 사용자 정보 가져오기
        String userName = (String) session.getAttribute("userName");
        String userId = (String) session.getAttribute("userId");

        // 로그인하지 않은 경우
        if (userName == null || userId == null) {
            return "redirect:/Login";
        }

        model.addAttribute("userName", userName);
        model.addAttribute("userId", userId);

        return "Main";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        // 세션 무효화
        session.invalidate();
        return "redirect:/Login";
    }
}
```

**파일 생성**: `Client/src/main/resources/templates/Main.mustache`

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>메인 페이지</title>
    <style>
        .container { max-width: 800px; margin: 50px auto; }
        .user-info { background: #f0f0f0; padding: 20px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>메인 페이지</h1>

        <div class="user-info">
            <p><strong>환영합니다!</strong></p>
            <p>이름: {{userName}}</p>
            <p>아이디: {{userId}}</p>
        </div>

        <div>
            <button onclick="location.href='/logout'">로그아웃</button>
        </div>
    </div>
</body>
</html>
```

---

## 5. 보안 Best Practices

### 5.1 비밀번호 정책

**강력한 비밀번호 요구사항**:
```java
@Pattern(
    regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
    message = "비밀번호는 최소 8자, 대문자, 소문자, 숫자, 특수문자를 포함해야 합니다."
)
private String pw;
```

**검증 항목**:
- 최소 8자 이상
- 대문자 1개 이상
- 소문자 1개 이상
- 숫자 1개 이상
- 특수문자 1개 이상
- 이전 비밀번호와 다름 (DB에 이력 저장)

### 5.2 JWT 토큰 저장 위치

| 저장소 | 보안 수준 | 권장 사항 |
|--------|-----------|-----------|
| **LocalStorage** | ⚠️ 낮음 | XSS 공격에 취약, 피하기 |
| **SessionStorage** | ⚠️ 낮음 | 개발 단계에서만 사용 |
| **HttpOnly Cookie** | ✅ 높음 | **운영 환경 권장** |
| **Memory (변수)** | ✅ 높음 | 새로고침 시 소실 |

**HttpOnly Cookie 구현 예시** (Server):
```java
@PostMapping("/api/login")
public ResponseEntity<?> login(
        @RequestBody LoginRequest request,
        HttpServletResponse response
) {
    LoginReply reply = loginService.Login(request);

    if (reply.isRet()) {
        // JWT를 HttpOnly 쿠키로 설정
        Cookie cookie = new Cookie("jwtToken", reply.getToken());
        cookie.setHttpOnly(true);  // JavaScript 접근 불가
        cookie.setSecure(true);    // HTTPS에서만 전송
        cookie.setPath("/");
        cookie.setMaxAge(3600);    // 1시간

        response.addCookie(cookie);

        // 응답 본문에서는 토큰 제거
        reply.setToken(null);
    }

    return ResponseEntity.ok(reply);
}
```

### 5.3 HTTPS 적용

**개발 환경**:
```properties
# application.properties
server.ssl.enabled=true
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=your-password
server.ssl.key-store-type=PKCS12
```

**자체 서명 인증서 생성** (테스트용):
```bash
keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore keystore.p12 -validity 3650 \
  -storepass password
```

**운영 환경**: Let's Encrypt 또는 상용 SSL 인증서 사용

### 5.4 환경변수 관리

**절대 코드에 포함하지 말 것**:
- JWT Secret Key
- 데이터베이스 비밀번호
- API 키

**환경변수 설정** (Linux/Mac):
```bash
export JWT_SECRET="your-actual-production-secret-key-min-32-chars"
export DB_PASSWORD="your-database-password"
```

**application.properties**:
```properties
jwt.secret=${JWT_SECRET}
spring.datasource.password=${DB_PASSWORD}
```

**Docker Compose**:
```yaml
services:
  app:
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - DB_PASSWORD=${DB_PASSWORD}
    env_file:
      - .env  # .gitignore에 추가!
```

### 5.5 CORS 설정

클라이언트와 서버가 다른 도메인일 경우 CORS 설정 필요:

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("http://localhost:8081")  // Client 도메인
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("*")
                .allowCredentials(true)  // 쿠키 허용
                .maxAge(3600);
    }
}
```

### 5.6 Rate Limiting (요청 제한)

무차별 대입 공격 방지:

```java
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final Map<String, Integer> requestCounts = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_MINUTE = 10;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String clientIp = request.getRemoteAddr();
        int count = requestCounts.getOrDefault(clientIp, 0);

        if (count >= MAX_REQUESTS_PER_MINUTE) {
            response.sendError(429, "Too Many Requests");
            return;
        }

        requestCounts.put(clientIp, count + 1);

        // 1분 후 리셋 (ScheduledExecutorService 사용)

        filterChain.doFilter(request, response);
    }
}
```

---

## 6. 트러블슈팅 가이드

### 6.1 자주 발생하는 오류

#### 오류 1: `java.lang.IllegalArgumentException: JWT secret key must be at least 256 bits`

**원인**: JWT Secret Key가 너무 짧음 (32자 미만)

**해결**:
```properties
# application.properties
jwt.secret=this-is-a-very-long-secret-key-with-at-least-256-bits-length
```

#### 오류 2: `401 Unauthorized` (토큰은 있는데 인증 실패)

**원인 1**: 토큰 형식 오류
```
# 잘못된 형식
Authorization: eyJhbGc...

# 올바른 형식
Authorization: Bearer eyJhbGc...
```

**원인 2**: 토큰 만료
```bash
# 토큰 디코딩하여 exp 확인
echo "eyJhbGc..." | base64 -d
```

**원인 3**: Secret Key 불일치 (서버 재시작 시 변경됨)

**해결**: application.properties에 고정된 secret 사용

#### 오류 3: `403 Forbidden`

**원인**: 인증은 성공했지만 권한 부족

**해결**: SecurityConfig에서 엔드포인트 권한 확인
```java
.requestMatchers("/api/admin/**").hasRole("ADMIN")
.requestMatchers("/api/users/**").hasAnyRole("USER", "ADMIN")
```

#### 오류 4: CORS 오류

**브라우저 콘솔**:
```
Access to XMLHttpRequest at 'http://localhost:8080/api/login'
from origin 'http://localhost:8081' has been blocked by CORS policy
```

**해결**: CORS 설정 추가 (5.5절 참조)

#### 오류 5: `ExpiredJwtException`

**원인**: 토큰 만료

**해결**: Refresh Token 구현 또는 재로그인 요청
```java
catch (ExpiredJwtException ex) {
    // Client에게 401 응답
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
}
```

### 6.2 디버깅 팁

#### 1. JWT 내용 확인

온라인 디코더: https://jwt.io

또는 커맨드라인:
```bash
# Header + Payload 디코딩
echo "eyJhbGc..." | cut -d. -f1-2 | base64 -d
```

#### 2. SecurityContext 확인

```java
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
System.out.println("Principal: " + auth.getPrincipal());
System.out.println("Authenticated: " + auth.isAuthenticated());
```

#### 3. 필터 실행 순서 로깅

```java
@Override
protected void doFilterInternal(...) {
    System.out.println("JwtAuthenticationFilter executed for: " + request.getRequestURI());
    // ...
}
```

#### 4. RestTemplate 요청/응답 로깅

```java
@Bean
public RestTemplate restTemplate() {
    RestTemplate restTemplate = new RestTemplate();

    // 로깅 Interceptor 추가
    restTemplate.setInterceptors(Collections.singletonList(
        (request, body, execution) -> {
            System.out.println("Request: " + request.getURI());
            System.out.println("Headers: " + request.getHeaders());
            ClientHttpResponse response = execution.execute(request, body);
            System.out.println("Response Status: " + response.getStatusCode());
            return response;
        }
    ));

    return restTemplate;
}
```

### 6.3 테스트 코드 작성

#### JWT 생성/검증 테스트

```java
@SpringBootTest
class JwtTokenProviderTest {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Test
    void testGenerateAndValidateToken() {
        // Given
        String userId = "testuser";

        // When
        String token = jwtTokenProvider.generateToken(userId);

        // Then
        assertTrue(jwtTokenProvider.validateToken(token));
        assertEquals(userId, jwtTokenProvider.getUserIdFromToken(token));
    }

    @Test
    void testExpiredToken() throws InterruptedException {
        // Given: 만료 시간 1초로 설정
        String token = jwtTokenProvider.generateToken("testuser");

        // When: 2초 대기
        Thread.sleep(2000);

        // Then: 만료된 토큰은 검증 실패
        assertFalse(jwtTokenProvider.validateToken(token));
    }
}
```

#### 로그인 통합 테스트

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class LoginIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testLoginSuccess() throws Exception {
        // Given
        LoginRequest request = new LoginRequest("testuser", "password123");

        // When & Then
        mockMvc.perform(post("/api/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ret").value(true))
                .andExpect(jsonPath("$.token").exists());
    }

    @Test
    void testAccessProtectedEndpointWithoutToken() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testAccessProtectedEndpointWithToken() throws Exception {
        // Given: 토큰 생성
        String token = jwtTokenProvider.generateToken("testuser");

        // When & Then
        mockMvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("testuser"));
    }
}
```

---

## 7. 다음 단계 학습 로드맵

### 7.1 Refresh Token 구현

Access Token 만료 시 자동 갱신:

```java
@PostMapping("/api/refresh")
public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
    String refreshToken = request.getRefreshToken();

    if (jwtTokenProvider.validateToken(refreshToken)) {
        String userId = jwtTokenProvider.getUserIdFromToken(refreshToken);

        // 새 Access Token 발급
        String newAccessToken = jwtTokenProvider.generateToken(userId);

        return ResponseEntity.ok(new TokenResponse(newAccessToken));
    }

    return ResponseEntity.status(401).body("Invalid refresh token");
}
```

### 7.2 역할 기반 인가 (RBAC)

```java
@Entity
public class StdUser {
    // ...

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = new HashSet<>();
}

public enum Role {
    ROLE_USER,
    ROLE_ADMIN,
    ROLE_MODERATOR
}
```

```java
@GetMapping("/api/admin/users")
@PreAuthorize("hasRole('ADMIN')")  // 관리자만 접근 가능
public List<UserDto> getAllUsers() {
    // ...
}
```

### 7.3 소셜 로그인 (OAuth2)

```gradle
implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
```

```properties
spring.security.oauth2.client.registration.google.client-id=your-client-id
spring.security.oauth2.client.registration.google.client-secret=your-client-secret
```

### 7.4 이메일 인증

```java
@PostMapping("/api/signup")
public ResponseEntity<?> signup(@RequestBody SignupRequest request) {
    // 1. 사용자 생성 (비활성 상태)
    StdUser user = createUser(request);
    user.setEnabled(false);

    // 2. 인증 토큰 생성
    String verificationToken = UUID.randomUUID().toString();

    // 3. 이메일 전송
    emailService.sendVerificationEmail(user.getEmail(), verificationToken);

    return ResponseEntity.ok("인증 이메일을 발송했습니다.");
}
```

### 7.5 2단계 인증 (2FA)

TOTP (Time-based One-Time Password) 구현:

```gradle
implementation 'com.warrenstrange:googleauth:1.5.0'
```

---

## 8. 요약 및 체크리스트

### 구현 완료 체크리스트

- [ ] **Step 1**: BCrypt로 비밀번호 암호화
- [ ] **Step 2**: JWT 유틸리티 클래스 작성
- [ ] **Step 3**: 로그인 시 JWT 발급
- [ ] **Step 4**: JWT 검증 필터 구현
- [ ] **Step 5**: Spring Security 설정
- [ ] **Step 6**: 인증이 필요한 API 추가
- [ ] **Step 7**: Client에서 JWT 저장 및 전송
- [ ] **Step 8**: 메인 페이지 구현
- [ ] **보안**: HTTPS 적용
- [ ] **보안**: 환경변수로 Secret Key 관리
- [ ] **보안**: CORS 설정
- [ ] **테스트**: 단위 테스트 작성
- [ ] **테스트**: 통합 테스트 작성

### 핵심 개념 복습

1. **Authentication vs Authorization**
   - Authentication: 사용자가 누구인지 확인 (로그인)
   - Authorization: 사용자가 무엇을 할 수 있는지 결정 (권한)

2. **JWT 구조**
   - Header: 알고리즘 정보
   - Payload: 사용자 데이터 (암호화 안 됨!)
   - Signature: 위변조 방지

3. **Filter Chain**
   - 모든 요청은 필터 체인을 거침
   - JWT 필터에서 토큰 검증
   - SecurityContext에 인증 정보 저장

4. **BCrypt**
   - 비밀번호는 절대 평문 저장 금지
   - Salt 자동 생성
   - 느린 해싱으로 무차별 대입 공격 방어

### 주의사항

⚠️ **절대 하지 말아야 할 것**:
1. 비밀번호 평문 저장
2. JWT Secret Key 코드에 포함
3. Payload에 민감한 정보 저장
4. HTTPS 없이 운영 환경 배포
5. CORS를 모든 도메인에 허용 (`*`)

✅ **반드시 해야 할 것**:
1. 비밀번호 BCrypt 암호화
2. JWT Secret Key 환경변수 관리
3. HTTPS 적용
4. 토큰 만료 시간 설정 (1시간 권장)
5. Refresh Token 구현

---

## 9. 추가 학습 자료

### 공식 문서
- [Spring Security 공식 문서](https://docs.spring.io/spring-security/reference/index.html)
- [JWT.io](https://jwt.io) - JWT 디코더 및 라이브러리
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - 웹 보안 취약점

### 추천 도서
- "Spring Security in Action" by Laurentiu Spilca
- "OAuth 2 in Action" by Justin Richer

### 유용한 도구
- [Postman](https://www.postman.com/) - API 테스트
- [Burp Suite](https://portswigger.net/burp) - 보안 테스트
- [SonarQube](https://www.sonarqube.org/) - 코드 품질 분석

---

**축하합니다!** 이제 Spring Security와 JWT를 이용한 안전한 인증 시스템을 구축할 수 있습니다.

질문이나 추가 설명이 필요한 부분이 있다면 언제든지 물어보세요!
