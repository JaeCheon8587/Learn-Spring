# Spring Security & JWT 종합 학습 가이드

**👋 안녕하세요!** 이 가이드는 Spring Security와 JWT를 처음 배우는 개발자를 위해 작성되었습니다. 복잡한 개념도 쉽게 이해할 수 있도록 구성했습니다.

## 목차
1. [Spring Security 기초](#1-spring-security-기초)
2. [JWT 이해하기](#2-jwt-이해하기)
3. [클라이언트-서버 인증 흐름](#3-클라이언트-서버-인증-흐름)
4. [단계별 구현 가이드](#4-단계별-구현-가이드)
5. [보안 Best Practices](#5-보안-best-practices)
6. [트러블슈팅 가이드](#6-트러블슈팅-가이드)
7. [다음 단계 학습](#7-다음-단계-학습)

---

## 1. Spring Security 기초

### 1.1 Spring Security란?

**쉬운 설명**: Spring Security는 당신의 애플리케이션의 **"보안 경비원"**입니다.

- 🚪 **출입 관리**: 누가 시스템에 접근할 수 있는지 결정 (Authentication)
- 👮 **권한 관리**: 접근한 사람이 무엇을 할 수 있는지 결정 (Authorization)
- 🛡️ **공격 방어**: 보안 위협으로부터 시스템 보호

**실제 예시**:
```
회사 사무실 = 애플리케이션
보안 경비원 = Spring Security
신분증 = 인증 정보 (사용자명 + 비밀번호)
직원 ID = 토큰 (JWT)
직원 권한 = 역할 (ROLE_USER, ROLE_ADMIN 등)

회사 방문자 → 신분증 확인 → 직원 ID 발급 → 권한에 따라 접근 제어
사용자 요청 → 자격증명 확인 → 토큰 발급 → 역할에 따라 API 접근 제어
```

### 1.2 Spring Security 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP Request                              │
│                           ↓                                      │
├─────────────────────────────────────────────────────────────────┤
│                  Spring Security Filter Chain                     │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 1. SecurityContextHolder (현재 사용자 정보 저장소)        │   │
│  │    └─ Authentication 객체 보유                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 2. Filter Chain (여러 필터가 순서대로 실행)              │   │
│  │    - CsrfFilter (CSRF 공격 방어)                        │   │
│  │    - JwtAuthenticationFilter (JWT 검증) ← 우리가 구현    │   │
│  │    - UsernamePasswordAuthenticationFilter (로그인)       │   │
│  │    - ...기타 필터들                                       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 3. AuthenticationManager                                 │   │
│  │    └─ 사용자 인증 처리                                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 4. AccessDecisionManager                                 │   │
│  │    └─ 권한 확인 (URL 접근 가능한지)                      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
├─────────────────────────────────────────────────────────────────┤
│                    Controller/API 실행                            │
│                           ↓                                      │
├─────────────────────────────────────────────────────────────────┤
│                        HTTP Response                              │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 핵심 개념: Authentication vs Authorization

| 개념 | Authentication (인증) | Authorization (인가) |
|------|----------------------|---------------------|
| 의미 | **누구인가?** 신원 확인 | **무엇을 할 수 있는가?** 권한 확인 |
| 예시 | ID/PW로 로그인 확인 | ROLE_ADMIN만 관리자 페이지 접근 |
| 비유 | 신분증 확인 | 직원 ID 확인 후 업무실 접근 |
| Java | `Authentication` 객체 | `GrantedAuthority` 객체 |
| 순서 | 1번째 (먼저 실행) | 2번째 (나중에 실행) |

### 1.4 Filter Chain 상세 설명

**Filter**는 HTTP 요청 흐름에서 처리할 수 있는 특별한 객체입니다.

```
Request → [Filter1] → [Filter2] → [Filter3] → Controller → Response
                                ↓
                        (필터에서 처리 가능)
```

**Spring Security의 주요 필터들**:

1. **CsrfFilter**: 악의적인 웹사이트에서 자동으로 요청하는 것을 방지
2. **JwtAuthenticationFilter** (우리가 만들 것):
   - Authorization 헤더에서 JWT 토큰 추출
   - 토큰 유효성 검증
   - SecurityContext에 인증 정보 설정
3. **UsernamePasswordAuthenticationFilter**: 로그인 폼 처리

### 1.5 SecurityContext와 Authentication

```java
// SecurityContext: 현재 요청의 인증 정보 저장소
SecurityContext context = SecurityContextHolder.getContext();

// Authentication: 실제 인증 정보
Authentication auth = context.getAuthentication();

// Authentication의 구조
Authentication {
    principal: "user123",              // 사용자 ID
    credentials: "password_hashed",    // 비밀번호 (로그인 후 제거)
    authorities: [                     // 권한 목록
        GrantedAuthority("ROLE_USER"),
        GrantedAuthority("ROLE_ADMIN")
    ],
    authenticated: true                // 인증 여부
}
```

---

## 2. JWT 이해하기

### 2.1 JWT란?

**JWT (JSON Web Token)**: 사용자 정보를 안전하게 전달하는 방식

**비유**: 영화 티켓
```
┌─────────────────────────────────────┐
│ 영화 티켓 = JWT 토큰                 │
├─────────────────────────────────────┤
│ 영화: 나쁜 놈들                      │ ← Header (토큰 타입 정보)
│ 상영시간: 2024-01-15 19:00          │ ← Payload (사용자 정보)
│ 표적: 김철수                         │
│ 가격: 12000원                        │
│ 서명: [암호화된 서명]                │ ← Signature (위조 방지)
└─────────────────────────────────────┘
```

### 2.2 JWT 구조

JWT는 3개의 부분으로 구성되며, `.`(점)으로 구분됩니다:

```
eyJhbGciOiJIUzUxMiJ9.
eyJzdWIiOiJ1c2VyMTIzIiwicm9sZXMiOlsiUk9MRV9VU0VSIl0sImlhdCI6MTcwNDc5Nzc0MCwiZXhwIjoxNzA0ODAxMzQwfQ.
xxxxxxxxxxxxxxxxxx

[Header].[Payload].[Signature]
```

#### Part 1: Header (헤더)
토큰의 타입과 사용된 암호화 알고리즘을 명시합니다.

```json
{
  "alg": "HS512",      // 암호화 알고리즘 (HMAC SHA-512)
  "typ": "JWT"         // 토큰 타입
}
```

이를 Base64로 인코딩하면: `eyJhbGciOiJIUzUxMiJ9`

#### Part 2: Payload (페이로드)
실제 사용자 정보를 담는 부분입니다. ("Claim"이라고도 부릅니다)

```json
{
  "sub": "user123",                    // subject: 사용자 ID
  "roles": ["ROLE_USER"],              // 사용자 역할
  "iat": 1704797740,                   // issued at: 발급 시간 (Unix timestamp)
  "exp": 1704801340                    // expiration: 만료 시간 (1시간 후)
}
```

#### Part 3: Signature (서명)
위조 방지를 위해 Header + Payload를 암호화한 값입니다.

```
HMACSHA512(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

### 2.3 JWT 장단점 비교표

| 항목 | JWT | Session |
|------|-----|---------|
| 저장 위치 | 클라이언트 (로컬 스토리지/쿠키) | 서버 메모리/DB |
| 서버 부담 | 낮음 (검증만 함) | 높음 (저장/조회 필요) |
| 확장성 | 높음 (분산 시스템 용이) | 낮음 (서버 간 공유 필요) |
| 보안 | 토큰 탈취 위험 | CSRF 공격 위험 |
| 사용 경우 | API, 모바일 앱 | 웹 애플리케이션 |
| 크기 | 크다 (매 요청마다 전송) | 작다 (ID만 전송) |

### 2.4 JWT 사용 흐름

```
1. 로그인 요청
   사용자 → {"id": "user123", "pw": "secret"} → 서버

2. 검증 & 토큰 생성
   서버 → 비밀번호 검증 → JWT 생성
   JWT = Header.Payload.Signature

3. 토큰 반환
   서버 → "eyJhbGci..." → 클라이언트

4. 토큰 저장
   클라이언트 → 로컬 스토리지/HttpSession 저장

5. API 요청시 토큰 전달
   클라이언트 → GET /api/users/me
               Authorization: Bearer eyJhbGci...

6. 토큰 검증
   서버 → 서명 검증 → 만료 여부 확인 → 사용자 정보 추출

7. 요청 처리
   서버 → 요청 처리 후 데이터 반환
```

### 2.5 JWT 주의사항

#### ❌ JWT에 저장하면 안 되는 정보
```java
// 나쁜 예
JWT payload에 저장하면 안 되는 것:
{
    "password": "secret123",           // ❌ 비밀번호
    "creditCard": "1234-5678-9012",    // ❌ 신용카드 번호
    "ssn": "123-45-6789"               // ❌ 주민등록번호
}

// 이유: JWT는 Base64로 인코딩될 뿐 암호화되지 않음
// Base64는 누구나 디코드할 수 있습니다!
```

#### ✅ JWT에 저장해도 되는 정보
```java
// 좋은 예
JWT payload에 저장해도 되는 것:
{
    "sub": "user123",                  // ✅ 사용자 ID
    "roles": ["ROLE_USER"],            // ✅ 권한
    "name": "Kim Chulsu",              // ✅ 공개 정보
    "iat": 1704797740,                 // ✅ 발급 시간
    "exp": 1704801340                  // ✅ 만료 시간
}
```

---

## 3. 클라이언트-서버 인증 흐름

### 3.1 현재 프로젝트 구조

```
┌─────────────────┐                    ┌──────────────────┐
│   Client        │                    │     Server       │
│   (port 8081)   │                    │   (port 8080)    │
│                 │                    │                  │
│ • 뷰 렌더링     │  ←→ HTTP/REST API  │ • 인증/인가      │
│ • 로그인 폼     │                    │ • 데이터 처리    │
│ • 토큰 관리     │                    │ • DB 접근        │
│ • 요청 전송     │                    │                  │
└─────────────────┘                    └──────────────────┘
```

### 3.2 로그인 & 토큰 발급 흐름

```
Step 1: 사용자가 로그인 폼 제출
┌────────────────────────────────────────────────────────┐
│ 사용자가 LoginController에서 /Login/UserAccount POST  │
│ Body: {id: "user123", pw: "password123"}              │
└────────────────────────────────────────────────────────┘
                         ↓
Step 2: Client LoginService가 Server에 요청 전송
┌────────────────────────────────────────────────────────┐
│ RestTemplate.post(                                    │
│   "http://localhost:8080/api/auth/login",             │
│   LoginRequest                                         │
│ )                                                      │
└────────────────────────────────────────────────────────┘
                         ↓
Step 3: Server AuthController에서 처리
┌────────────────────────────────────────────────────────┐
│ AuthService.login() 실행:                              │
│ 1. DB에서 사용자 조회                                 │
│ 2. BCrypt로 비밀번호 검증                              │
│ 3. JWT 토큰 생성                                       │
│    - Access Token (1시간)                              │
│    - Refresh Token (2주)                               │
│ 4. 응답 반환                                           │
└────────────────────────────────────────────────────────┘
                         ↓
Step 4: Client에서 토큰 수신
┌────────────────────────────────────────────────────────┐
│ LoginReply {                                           │
│   ret: true,                                           │
│   msg: "로그인 성공",                                  │
│   userDto: {...},                                      │
│   accessToken: "eyJhbGci...",                          │
│   refreshToken: "eyJhbGci..."                          │
│ }                                                      │
└────────────────────────────────────────────────────────┘
                         ↓
Step 5: Client에서 토큰 저장
┌────────────────────────────────────────────────────────┐
│ JwtTokenStore.saveTokens(session, accessToken, ...)   │
│ HttpSession {                                          │
│   jwt_access_token: "eyJhbGci...",                     │
│   jwt_refresh_token: "eyJhbGci...",                    │
│   user_id: "user123"                                   │
│ }                                                      │
└────────────────────────────────────────────────────────┘
                         ↓
Step 6: 브라우저 리다이렉트
┌────────────────────────────────────────────────────────┐
│ redirect:/Home (로그인 후 홈 페이지로 이동)             │
└────────────────────────────────────────────────────────┘
```

### 3.3 API 호출 흐름 (인증 필요)

```
Step 1: 홈 페이지 요청
┌────────────────────────────────────────────────────────┐
│ Client에서 GET /Home 요청                              │
│ HomeController.home() 실행                             │
└────────────────────────────────────────────────────────┘
                         ↓
Step 2: Server API 호출
┌────────────────────────────────────────────────────────┐
│ RestTemplate.get(                                      │
│   "http://localhost:8080/api/users/me",               │
│   UserDto.class                                        │
│ )                                                      │
│                                                        │
│ 🔑 JwtRequestInterceptor가 자동으로 토큰 추가:         │
│ Authorization: Bearer eyJhbGci...                      │
└────────────────────────────────────────────────────────┘
                         ↓
Step 3: Server에서 토큰 검증
┌────────────────────────────────────────────────────────┐
│ JwtAuthenticationFilter.doFilterInternal() 실행        │
│ 1. Authorization 헤더에서 토큰 추출                     │
│    "Bearer eyJhbGci..." → "eyJhbGci..."               │
│ 2. JwtTokenProvider.validateToken() 검증              │
│    - 서명 확인 (위조 방지)                              │
│    - 만료 시간 확인                                    │
│ 3. 토큰이 유효하면:                                    │
│    - userId, roles 추출                               │
│    - Authentication 객체 생성                          │
│    - SecurityContext에 저장                            │
│ 4. 토큰이 유효하지 않으면:                              │
│    → 401 Unauthorized 응답                            │
└────────────────────────────────────────────────────────┘
                         ↓
Step 4: Controller 실행
┌────────────────────────────────────────────────────────┐
│ UserController.getCurrentUser() 실행                   │
│ 1. SecurityContext에서 현재 사용자 정보 추출            │
│ 2. DB에서 사용자 정보 조회                              │
│ 3. UserDto 반환                                        │
└────────────────────────────────────────────────────────┘
                         ↓
Step 5: Client에서 응답 처리
┌────────────────────────────────────────────────────────┐
│ UserDto {                                              │
│   seq: 1,                                              │
│   id: "user123",                                       │
│   name: "Kim Chulsu",                                  │
│   email: "kim@example.com",                            │
│   role: "ROLE_USER"                                    │
│ }                                                      │
│                                                        │
│ Model에 추가해서 Mustache 템플릿 렌더링                │
└────────────────────────────────────────────────────────┘
```

### 3.4 401 Unauthorized 처리 흐름

```
시나리오: 토큰이 만료된 경우

Step 1: API 호출 (만료된 토큰)
┌────────────────────────────────────────────────────────┐
│ GET /api/users/me                                      │
│ Authorization: Bearer eyJhbGci... (만료됨)             │
└────────────────────────────────────────────────────────┘
                         ↓
Step 2: JwtAuthenticationFilter에서 검증
┌────────────────────────────────────────────────────────┐
│ tokenProvider.validateToken(token) → false             │
│ 이유: exp (만료 시간) < 현재 시간                       │
└────────────────────────────────────────────────────────┘
                         ↓
Step 3: 401 Unauthorized 응답
┌────────────────────────────────────────────────────────┐
│ HTTP 401 Unauthorized                                  │
│ {"error": "Unauthorized"}                              │
└────────────────────────────────────────────────────────┘
                         ↓
Step 4: Client 에러 처리
┌────────────────────────────────────────────────────────┐
│ RestTemplateConfig의 errorHandler가 감지:              │
│ if (response.getStatusCode() == HttpStatus.UNAUTHORIZED)
│ {                                                      │
│     // 옵션 1: 자동 토큰 갱신 시도 (Refresh Token)    │
│     newToken = refreshAccessToken(refreshToken)       │
│     // 옵션 2: 로그인 페이지로 리다이렉트               │
│     return redirect:/Login                             │
│ }                                                      │
└────────────────────────────────────────────────────────┘
```

---

## 4. 단계별 구현 가이드

### 4.1 Step 1: BCrypt 비밀번호 해싱 이해하기

**현재 상태**: 비밀번호가 평문으로 저장됨
```sql
-- DB에 저장된 패턴
SELECT ID, PASSWORD FROM STD_USER;
user123    | password123        ← ❌ 평문 저장 (매우 위험)
```

**BCrypt란?**: 일방향 해싱 알고리즘 (복호화 불가능)

```java
// BCrypt 작동 원리
평문: "password123"
↓
BCrypt 해싱: $2a$10$4eqIf09DQd/vJ7/84N5Zoe.fGFZYOvnL6XCB4PEXwAVxKKkLXVS5K
             ↑
             ($2a$: BCrypt 버전, 10: cost factor)

// 특징:
// 1. 매번 다른 결과 (무작위 salt 사용)
// 2. 복호화 불가능
// 3. 검증만 가능 (matches 메서드)
```

**BCrypt 검증 과정**:
```java
PasswordEncoder encoder = new BCryptPasswordEncoder();

// 비밀번호 저장시
String hashedPassword = encoder.encode("password123");
// hashedPassword = "$2a$10$4eqIf09DQd/vJ7/84N5Zoe..."

// 로그인시 검증
boolean isPasswordValid = encoder.matches("password123", hashedPassword);
// → true (일치함)

boolean isPasswordValid = encoder.matches("wrongpassword", hashedPassword);
// → false (불일치)
```

### 4.2 Step 2: JWT 토큰 생성/검증 이해하기

```java
// 토큰 생성 원리
public String generateAccessToken(String userId, List<String> roles) {
    // 1단계: Payload 만들기
    Claims claims = Jwts.claims().subject(userId).build();
    claims.put("roles", roles);

    // 2단계: 시간 설정
    Date now = new Date();
    Date expirationDate = new Date(now.getTime() + 3600000); // 1시간 후

    // 3단계: 토큰 생성 (Header + Payload + Signature)
    return Jwts.builder()
            .claims(claims)              // Payload 설정
            .issuedAt(now)               // iat 클레임
            .expiration(expirationDate)  // exp 클레임
            .signWith(key, SignatureAlgorithm.HS512)  // 서명
            .compact();                  // 완성
}

// 토큰 검증 원리
public boolean validateToken(String token) {
    try {
        // 1단계: 서명 검증
        // (secret key로 다시 계산해서 전달받은 서명과 비교)

        // 2단계: 구문 검증
        // (Header, Payload, Signature 형식 확인)

        // 3단계: 만료 시간 검증
        // (현재 시간이 exp 이전인지 확인)

        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);  // 모든 검증 실행

        return true;  // 모든 검증 통과
    } catch (JwtException | IllegalArgumentException e) {
        return false; // 검증 실패
    }
}

// 토큰에서 정보 추출
public String getUserIdFromToken(String token) {
    // 검증된 토큰의 Payload에서 subject 추출
    return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getSubject();  // sub 클레임 = userId
}
```

### 4.3 Step 3: Spring Security Filter 이해하기

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // OncePerRequestFilter: 요청당 정확히 한 번만 실행

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) {
        try {
            // Step 1: Authorization 헤더에서 JWT 추출
            String bearerToken = request.getHeader("Authorization");
            // "Authorization: Bearer eyJhbGci..." → "eyJhbGci..."

            String token = null;
            if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
                token = bearerToken.substring(7);  // "Bearer " 제거
            }

            // Step 2: 토큰 검증
            if (token != null && tokenProvider.validateToken(token)) {
                String userId = tokenProvider.getUserIdFromToken(token);
                List<String> roles = tokenProvider.getRolesFromToken(token);

                // Step 3: Authentication 객체 생성
                UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                        userId,           // principal (사용자 ID)
                        null,             // credentials (로그인 후 삭제)
                        roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList())  // authorities (권한)
                    );

                // Step 4: SecurityContext에 저장
                // (이후 컨트롤러에서 @PreAuthorize, SecurityContextHolder 사용 가능)
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (Exception e) {
            log.error("JWT authentication failed", e);
        }

        // Step 5: 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }
}
```

### 4.4 Step 4: RestTemplate Interceptor 이해하기

```java
@Component
public class JwtRequestInterceptor implements ClientHttpRequestInterceptor {
    // Interceptor: RestTemplate의 모든 요청을 가로채서 처리

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body,
                                        ClientHttpRequestExecution execution) {
        // Step 1: 세션에서 토큰 가져오기
        String token = tokenStore.getAccessToken(httpSession);

        // Step 2: 토큰이 있으면 Authorization 헤더 추가
        if (token != null) {
            // GET /api/users/me
            // ↓
            // GET /api/users/me
            // Authorization: Bearer eyJhbGci...
            request.getHeaders().add("Authorization", "Bearer " + token);
        }

        // Step 3: 요청 실행 (실제 HTTP 통신)
        ClientHttpResponse response = execution.execute(request, body);

        // Step 4: 응답 처리 (에러 핸들링 가능)
        if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            // 토큰 만료시 처리
            // 옵션 1: Refresh Token으로 새 토큰 요청
            // 옵션 2: 로그인 페이지로 리다이렉트
        }

        return response;
    }
}
```

### 4.5 Step 5: 권한 확인 (Authorization)

```java
// 방식 1: @PreAuthorize (메서드 레벨)
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")  // ROLE_ADMIN만 접근 가능
    public String getDashboard() {
        return "관리자 대시보드";
    }
}

// 방식 2: SecurityConfig (URL 레벨)
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/auth/**").permitAll()      // 모두 접근 허용
            .requestMatchers("/api/admin/**").hasRole("ADMIN") // ADMIN만 접근
            .requestMatchers("/api/users/**").authenticated()  // 인증된 사용자만
            .anyRequest().authenticated()                      // 나머지는 인증 필요
        );
        return http.build();
    }
}

// 방식 3: SecurityContextHolder (코드 레벨)
@GetMapping("/me")
public UserDto getCurrentUser() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    // auth.getPrincipal() = "user123"
    // auth.getAuthorities() = [ROLE_USER]
    // auth.isAuthenticated() = true

    String userId = (String) auth.getPrincipal();
    UserDto user = userService.getUserById(userId);
    return user;
}
```

---

## 5. 보안 Best Practices

### 5.1 비밀번호 정책

```java
// ❌ 나쁜 예
public class SignupService {
    public void signup(String id, String password) {
        // 평문 저장
        user.setPassword(password);
        userRepository.save(user);
    }
}

// ✅ 좋은 예
public class SignupService {
    @Autowired
    private PasswordEncoder passwordEncoder;  // BCryptPasswordEncoder

    public void signup(String id, String password) {
        // 비밀번호 정책 검증
        if (!isValidPassword(password)) {
            throw new RuntimeException("비밀번호는 8자 이상, 대소문자/숫자/특수문자 포함 필요");
        }

        // 해싱해서 저장
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }

    private boolean isValidPassword(String password) {
        // 8자 이상
        if (password.length() < 8) return false;
        // 대문자 포함
        if (!password.matches(".*[A-Z].*")) return false;
        // 소문자 포함
        if (!password.matches(".*[a-z].*")) return false;
        // 숫자 포함
        if (!password.matches(".*[0-9].*")) return false;
        // 특수문자 포함
        if (!password.matches(".*[!@#$%^&*].*")) return false;
        return true;
    }
}
```

### 5.2 JWT Secret 관리

```java
// ❌ 나쁜 예
@Component
public class JwtTokenProvider {
    private String secretKey = "mysecret";  // ❌ Git에 노출됨
}

// ✅ 좋은 예
@Component
public class JwtTokenProvider {
    @Value("${jwt.secret}")  // ✅ application.properties에서 로드
    private String secretKey;
}

// application.properties
# 개발 환경
jwt.secret=aW5zZXJ0LXlvdXItMjU2LWJpdC1iYXNlNjQtZW5jb2RlZC1zZWNyZXQta2V5LWhlcmU=

// application-prod.properties
# 운영 환경 (환경변수에서 주입)
jwt.secret=${JWT_SECRET}

// 실행시
export JWT_SECRET="production-secret-key-base64-encoded"
./gradlew bootRun --args='--spring.profiles.active=prod'
```

**JWT Secret 생성 방법**:
```bash
# 256비트 (32바이트) 랜덤 문자열을 Base64로 인코딩
# Linux/Mac
openssl rand -base64 32

# 예시 결과
# aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkL0=

# Windows PowerShell
[Convert]::ToBase64String((1..32 | % {[byte]$_}) | Get-Random -Count 32)
```

### 5.3 토큰 저장 위치

```java
// ❌ 나쁜 예 (localStorage 사용)
// JavaScript에서
localStorage.setItem('jwt_token', token);  // ❌ XSS 공격에 취약

// ✅ 좋은 예 (HttpOnly 쿠키)
// Server에서
HttpOnly cookie를 설정하면:
Set-Cookie: jwt_token=eyJhbGci...; HttpOnly; Secure; SameSite=Strict

// JavaScript에서 접근 불가능 → XSS 공격 방지
// 자동으로 매 요청에 포함됨

// 현재 프로젝트의 경우:
// HttpSession 사용 (서버 기반, 안전함)
session.setAttribute("jwt_access_token", accessToken);
```

### 5.4 HTTPS 적용

```properties
# Server의 application-prod.properties
server.ssl.enabled=true
server.ssl.key-store=/etc/ssl/keystore.p12
server.ssl.key-store-password=${SSL_KEYSTORE_PASSWORD}
server.ssl.key-store-type=PKCS12

# Client의 application-prod.properties
server.servlet.context-path=/
server.api.url=https://api.example.com  # HTTP → HTTPS로 변경
```

**HTTPS 자격증명 생성** (Let's Encrypt 무료):
```bash
# Certbot 설치 및 실행
sudo apt-get install certbot
sudo certbot certonly --standalone -d api.example.com

# PKCS12 형식으로 변환
sudo openssl pkcs12 -export -in /etc/letsencrypt/live/api.example.com/fullchain.pem \
  -inkey /etc/letsencrypt/live/api.example.com/privkey.pem \
  -out /etc/ssl/keystore.p12 -name tomcat
```

### 5.5 에러 메시지 보안

```java
// ❌ 나쁜 예 (정보 유출)
@PostMapping("/login")
public ResponseEntity<?> login(LoginRequest request) {
    try {
        // ...
    } catch (Exception e) {
        return ResponseEntity.status(400)
            .body("Error: " + e.getMessage());  // ❌ 스택 트레이스 노출
    }
}

// ✅ 좋은 예 (일반적인 메시지)
@PostMapping("/login")
public ResponseEntity<?> login(LoginRequest request) {
    Optional<StdUser> userOpt = userRepository.findById(request.getId());

    if (userOpt.isEmpty()) {
        // ❌ 사용자를 찾을 수 없습니다 (사용자 정보 노출)
        // ✅ 사용자 정보가 일치하지 않습니다 (동일한 메시지)
        return ResponseEntity.status(401)
            .body("사용자 정보가 일치하지 않습니다");
    }

    StdUser user = userOpt.get();
    if (!passwordEncoder.matches(request.getPw(), user.getPassword())) {
        return ResponseEntity.status(401)
            .body("사용자 정보가 일치하지 않습니다");  // ✅ 같은 메시지
    }

    // ...
}
```

---

## 6. 트러블슈팅 가이드

### 6.1 자주 발생하는 오류

#### 오류 1: `org.springframework.security.authentication.BadCredentialsException`

**증상**: 로그인 시 "Bad credentials" 에러

**원인**:
```java
// ❌ 비밀번호 검증 실패
if (plainPassword.equals(hashedPassword)) {  // 평문과 해시 비교 불가!
    // 항상 false
}
```

**해결**:
```java
// ✅ BCrypt matches 사용
if (passwordEncoder.matches(plainPassword, hashedPassword)) {
    // 올바른 비교
}
```

---

#### 오류 2: `javax.crypto.BadPaddingException: Given final block not properly padded`

**증상**: JWT 검증 시 위 에러 발생

**원인**:
```java
// ❌ Base64 디코드되지 않은 secret key 사용
private String secretKey = "mysecret";  // ❌ 일반 문자열
```

**해결**:
```java
// ✅ Base64 디코드된 secret key 사용
@PostConstruct
protected void init() {
    byte[] decodedKey = Base64.getDecoder().decode(secretKey);
    this.key = Keys.hmacShaKeyFor(decodedKey);
}
```

---

#### 오류 3: `CORS policy: No 'Access-Control-Allow-Origin' header`

**증상**: Client (8081)에서 Server (8080) API 호출 실패

**원인**: CORS 설정 누락

**해결**:
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(Arrays.asList("http://localhost:8081"));
    config.setAllowedMethods(Arrays.asList("*"));
    config.setAllowedHeaders(Arrays.asList("*"));
    config.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", config);
    return source;
}
```

---

#### 오류 4: `401 Unauthorized` 계속 발생

**증상**: 올바른 토큰인데도 401 에러

**원인**:
```java
// ❌ Authorization 헤더 형식 오류
Authorization: eyJhbGci...  // ❌ "Bearer " 없음

// ❌ 토큰 만료
// 1시간 후 자동 만료
```

**해결**:
```java
// ✅ 올바른 형식
Authorization: Bearer eyJhbGci...

// ✅ jwt.io에서 토큰 디코드해서 exp 확인
// exp: 1704801340 (Unix timestamp)
// date -d @1704801340  // 만료 시간 확인

// ✅ Refresh Token으로 새 토큰 발급
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"eyJhbGci...\"}"
```

---

#### 오류 5: `IllegalArgumentException: Illegal base64 character`

**증상**: JWT Secret이 유효하지 않음

**원인**: Base64 인코딩되지 않은 secret 사용

**해결**:
```bash
# ✅ 올바른 Base64 secret 생성
openssl rand -base64 32

# application.properties에 설정
jwt.secret=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkL0=
```

---

### 6.2 디버깅 팁

#### Tip 1: JWT 토큰 디코드

```bash
# https://jwt.io 에서 직접 확인 또는 CLI 도구 사용
jq -R 'split(".") | map(@base64d) | map(fromjson)' <<< "eyJhbGci..."

# 또는 Python 사용
python3 -c "import json, base64; print(json.dumps(json.loads(base64.b64decode(input().split('.')[1] + '==').decode()), indent=2))"
# 위 명령 실행 후 토큰 입력
```

#### Tip 2: 로그 레벨 상향

```properties
# application.properties에 추가
logging.level.com.example.demo.security=DEBUG
logging.level.org.springframework.security=DEBUG

# 그러면 로그에서 필터 체인 실행 순서 등을 볼 수 있습니다
```

#### Tip 3: Postman에서 테스트

```
1. 로그인 API 호출
POST http://localhost:8080/api/auth/login
Body (raw JSON):
{
    "id": "user123",
    "pw": "password123"
}

응답:
{
    "ret": true,
    "msg": "로그인 성공",
    "accessToken": "eyJhbGci...",
    "refreshToken": "eyJhbGci..."
}

2. 받은 accessToken 복사

3. 보호된 API 호출
GET http://localhost:8080/api/users/me

Authorization 탭에서:
- Type: Bearer Token
- Token: [위에서 복사한 accessToken]

그러면 자동으로 Authorization: Bearer eyJhbGci... 헤더가 추가됩니다
```

#### Tip 4: SecurityContext 내용 확인

```java
@GetMapping("/debug")
public Map<String, Object> debugSecurityContext() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    Map<String, Object> info = new HashMap<>();
    info.put("principal", auth.getPrincipal());
    info.put("authorities", auth.getAuthorities());
    info.put("authenticated", auth.isAuthenticated());

    return info;
}

// 응답
{
    "principal": "user123",
    "authorities": [
        {"authority": "ROLE_USER"}
    ],
    "authenticated": true
}
```

---

## 7. 다음 단계 학습

### 7.1 Refresh Token 구현

**목표**: Access Token 만료 후 자동으로 새 토큰 발급

```java
// 1. 토큰 갱신 엔드포인트
@PostMapping("/refresh")
public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
    String refreshToken = request.getRefreshToken();

    if (tokenProvider.validateToken(refreshToken)) {
        String userId = tokenProvider.getUserIdFromToken(refreshToken);
        String newAccessToken = tokenProvider.generateAccessToken(userId, roles);
        return ResponseEntity.ok(new TokenRefreshResponse(true, newAccessToken));
    }

    return ResponseEntity.status(401).body("Invalid refresh token");
}

// 2. Client에서 자동 갱신
// RestTemplate의 HttpClientErrorException 감지해서
// 401 응답시 refresh token으로 새 access token 요청
```

**학습 자료**: Spring Security 공식 가이드의 "Token Refresh" 섹션

---

### 7.2 역할 기반 인가 (RBAC)

**목표**: ROLE_ADMIN, ROLE_USER 등 역할에 따라 접근 제어

```java
// 1. Entity에 role 필드 추가 (이미 완료)
@Column(name = "ROLE")
private String role = "ROLE_USER";

// 2. SecurityConfig에서 역할별 접근 제어
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/api/admin/**").hasRole("ADMIN")
        .requestMatchers("/api/users/**").hasRole("USER")
        .anyRequest().authenticated()
    );
    return http.build();
}

// 3. 메서드 레벨 보안
@GetMapping("/admin/dashboard")
@PreAuthorize("hasRole('ADMIN')")
public String adminDashboard() {
    return "Admin Dashboard";
}
```

**학습 자료**:
- Spring Security `@PreAuthorize` 문서
- OWASP Authorization 가이드

---

### 7.3 OAuth2 소셜 로그인

**목표**: 구글, 카카오, 네이버 로그인 지원

```
기존 로그인: ID/PW → JWT 토큰
OAuth2 로그인: 구글 계정 → 구글 토큰 → JWT 토큰 발급
```

**학습 과정**:
1. OAuth2 기본 개념 학습
2. Spring Security OAuth2 문서 정독
3. Keycloak 또는 Auth0 같은 Identity Provider 이해

**참고 프로젝트**:
```bash
# Spring OAuth2 샘플
git clone https://github.com/spring-projects/spring-security-samples
cd spring-security-samples/servlet/spring-boot/java/oauth2/login
```

---

### 7.4 이메일 인증 (Email Verification)

**목표**: 회원가입시 이메일 인증 추가

```
1. 사용자 회원가입
2. 인증 코드 이메일 발송
3. 사용자가 이메일의 링크 클릭 또는 코드 입력
4. 이메일 인증 완료 → 계정 활성화
```

**구현 방식**:
```java
// 이메일 인증 코드를 JWT로 인코딩
String verificationToken = generateVerificationToken(userId);

// 이메일로 발송
sendVerificationEmail(email, verificationToken);

// 사용자가 링크 클릭시
GET /verify?token=eyJhbGci...

// 토큰 검증하고 계정 활성화
```

---

### 7.5 2단계 인증 (2FA)

**목표**: 추가 보안을 위해 OTP(일회성 비밀번호) 추가

```
1. 일반 로그인 (ID/PW)
2. OTP 입력 단계
3. 정상 로그인 완료

OTP 방식:
- TOTP (Time-based): Google Authenticator 앱 사용
- SMS OTP: 휴대폰으로 코드 수신
```

**라이브러리**:
```gradle
implementation 'com.warrenstrange:googleauth:1.5.0'
```

---

## 마무리

### 체크리스트

로그인 전에 다음을 확인하세요:

- [ ] 비밀번호가 BCrypt로 해싱되는가?
- [ ] JWT 토큰이 올바르게 생성되는가?
- [ ] Authorization 헤더에서 토큰을 올바르게 추출하는가?
- [ ] 토큰이 만료되었을 때 에러를 제대로 처리하는가?
- [ ] CORS 설정이 올바른가?
- [ ] 보안 로그를 기록하는가?

### 핵심 포인트

```
✅ 반드시 알아야 할 것:
1. BCrypt: 비밀번호는 절대 평문 저장하지 말 것
2. JWT: 토큰에 민감 정보 저장 금지
3. HTTPS: 운영 환경에서는 필수
4. 에러 메시지: 자세한 정보 노출 금지
5. 만료 시간: 적절한 길이 설정 필수

⚠️ 흔한 실수:
1. JWT Secret을 Git에 커밋
2. LocalStorage에 토큰 저장 (XSS 취약)
3. 만료된 토큰 계속 사용
4. CORS 와일드카드(*) 사용
5. 에러 메시지에 전체 스택 트레이스 노출
```

### 참고 자료 링크

**공식 문서**:
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/index.html)
- [JJWT GitHub](https://github.com/jwtk/jjwt)
- [JWT.io](https://jwt.io) - 토큰 디코드/검증

**보안 가이드**:
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

**실전 예제**:
- [Spring Security Samples](https://github.com/spring-projects/spring-security-samples)
- [Baeldung Spring Security 튜토리얼](https://www.baeldung.com/spring-security-authentication-and-registration)

---

**성공을 기원합니다! 🚀**

이 가이드를 따라 구현하면서 어려움이 생기면, 위의 "트러블슈팅 가이드" 섹션을 참고하거나 공식 문서를 확인해보세요.

행운을 빕니다! 💪
