# Spring Security & JWT 적용 계획서

## 목차
1. [현재 상태 분석](#1-현재-상태-분석)
2. [아키텍처 변경 계획](#2-아키텍처-변경-계획)
3. [구현 5단계 로드맵](#3-구현-5단계-로드맵)
4. [주의사항 및 Best Practices](#4-주의사항-및-best-practices)
5. [체크리스트](#5-체크리스트)
6. [마이그레이션 일정](#6-마이그레이션-일정)

---

## 1. 현재 상태 분석

### 1.1 보안 취약점 진단

#### 🚨 Critical (즉시 해결 필요)
- **평문 비밀번호 저장**: DB에 암호화 없이 password 저장 (StdUser.java)
- **인증 메커니즘 부재**: Spring Security 미적용, 세션/토큰 관리 없음
- **권한 관리 부재**: 모든 사용자가 동일한 권한, Role 개념 없음
- **DB 자격증명 노출**: application.properties에 평문 DB 패스워드

#### ⚠️ High (단기 해결 권장)
- **CSRF 보호 부재**: POST 요청 CSRF 토큰 없음
- **세션 관리 부재**: 로그인 후 상태 유지 메커니즘 없음
- **API 보호 부재**: Server REST API가 인증 없이 호출 가능
- **에러 정보 노출**: 상세한 에러 메시지 클라이언트 노출

#### ℹ️ Medium (중기 개선 사항)
- **HTTPS 미적용**: HTTP 통신으로 자격증명 전송
- **Rate Limiting 부재**: 무차별 대입 공격 방어 불가
- **로그 보안**: 민감정보 로깅 가능성

### 1.2 현재 아키텍처 분석

```
[Client:8081]                          [Server:8080]
┌─────────────────┐                    ┌─────────────────┐
│ LoginController │ ─RestTemplate→     │ LoginController │
│    (MVC)        │   POST /api/login  │  (@RestController)
│                 │                    │                 │
│ LoginService    │                    │ LoginService    │
│  (HTTP Client)  │                    │  (Business Logic)│
│                 │                    │                 │
│                 │                    │ UserRepository  │
│                 │                    │   (JPA)         │
│                 │                    │                 │
│ Mustache Views  │                    │ Oracle DB       │
│  (Template)     │                    │  (평문 저장)     │
└─────────────────┘                    └─────────────────┘
```

**특징**:
- Client는 stateless한 proxy 역할 (뷰 렌더링 + API 호출)
- Server가 실제 인증/인가 로직 보유
- RestTemplate 기반 동기 HTTP 통신
- 두 모듈 모두 Spring Boot 3.5.6 + Java 21

### 1.3 클라이언트-서버 분리 아키텍처의 보안 고려사항

**장점**:
- Server에만 Spring Security 적용으로 중앙화된 보안
- JWT 토큰 기반 stateless 인증에 최적

**도전과제**:
- Client에서 JWT 토큰 관리 및 전달 메커니즘 필요
- Server는 모든 요청 검증, Client는 토큰 저장/전송만 담당
- CORS 설정 필수 (Client:8081 → Server:8080)

---

## 2. 아키텍처 변경 계획

### 2.1 변경 후 아키텍처

```
[Client:8081]                                    [Server:8080]
┌──────────────────────┐                         ┌──────────────────────────┐
│ LoginController      │                         │ SecurityFilterChain      │
│  (MVC)               │                         │  - JwtAuthFilter         │
│                      │                         │  - CORS Config           │
│ LoginService         │  POST /api/auth/login   │                          │
│  + JwtTokenStore     │ ───────────────────→    │ AuthController           │
│  (Token 관리)        │    {id, pw}             │  - login()               │
│                      │                         │  - signup()              │
│ RestTemplateConfig   │ ←───────────────────    │                          │
│  + JWT Interceptor   │    {token, userDto}     │ AuthService              │
│  (Header 주입)       │                         │  + PasswordEncoder       │
│                      │                         │  + JwtTokenProvider      │
│ Mustache Views       │  GET /api/users/me      │                          │
│  (Session 기반 표시) │ ───────────────────→    │ UserController           │
│                      │  Authorization: Bearer  │  (인증 필요)             │
│                      │                         │                          │
│ HttpSession          │ ←───────────────────    │ UserRepository           │
│  - userId            │    {userDto}            │  (JPA)                   │
│  - jwtToken          │                         │                          │
└──────────────────────┘                         │ Oracle DB                │
                                                  │  - BCrypt 해시 저장      │
                                                  │  - USERS_SEQ             │
                                                  └──────────────────────────┘
```

### 2.2 핵심 변경사항

#### Server (port 8080) - 인증/인가 서버
1. **Spring Security 적용**
   - SecurityFilterChain 구성
   - JwtAuthenticationFilter 추가
   - PasswordEncoder (BCrypt) 설정

2. **JWT 토큰 발급**
   - JwtTokenProvider 구현
   - Access Token (1시간), Refresh Token (2주) 구조
   - 토큰에 userId, roles 포함

3. **API 엔드포인트 재구성**
   - `/api/auth/login` (public) - 토큰 발급
   - `/api/auth/signup` (public)
   - `/api/users/**` (authenticated) - JWT 필요

#### Client (port 8081) - 프레젠테이션 레이어
1. **JWT 토큰 관리**
   - HttpSession에 토큰 저장
   - JwtTokenStore 서비스 구현

2. **RestTemplate Interceptor**
   - 모든 Server 요청에 JWT 자동 주입
   - 401 Unauthorized 처리

3. **Session 기반 상태 관리**
   - 로그인 성공 시 토큰을 세션 저장
   - 로그아웃 시 세션 무효화
   - Mustache 템플릿에서 세션 기반 UI 제어

---

## 3. 구현 5단계 로드맵

### Phase 1: Server 기반 인프라 구축 (2-3일)
**목표**: Spring Security + JWT 인프라 완성

#### 3.1.1 의존성 추가
```gradle
// Server/build.gradle
dependencies {
    // 기존 의존성...

    // Spring Security
    implementation 'org.springframework.boot:spring-boot-starter-security'

    // JWT
    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.12.3'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.12.3'

    // Test
    testImplementation 'org.springframework.security:spring-security-test'
}
```

#### 3.1.2 JWT 토큰 프로바이더 구현
**파일**: `Server/src/main/java/com/example/demo/security/JwtTokenProvider.java`

```java
@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-validity:3600000}")
    private long accessTokenValidity; // 1시간

    @Value("${jwt.refresh-token-validity:1209600000}")
    private long refreshTokenValidity; // 2주

    private SecretKey key;

    @PostConstruct
    protected void init() {
        // Base64로 디코드된 secret key 생성
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        this.key = Keys.hmacShaKeyFor(decodedKey);
    }

    // Access Token 생성
    public String generateAccessToken(String userId, List<String> roles) {
        return createToken(userId, roles, accessTokenValidity);
    }

    // Refresh Token 생성
    public String generateRefreshToken(String userId) {
        return createToken(userId, Arrays.asList("REFRESH"), refreshTokenValidity);
    }

    // 실제 토큰 생성 로직
    private String createToken(String userId, List<String> roles, long validity) {
        Claims claims = Jwts.claims().subject(userId).build();
        claims.put("roles", roles);

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + validity);

        return Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(expirationDate)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.error("Invalid JWT token", e);
            return false;
        }
    }

    // 토큰에서 userId 추출
    public String getUserIdFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // 토큰에서 roles 추출
    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return (List<String>) claims.get("roles");
    }
}
```

**설정 추가**: `Server/src/main/resources/application.properties`
```properties
# JWT 설정 (Base64 256비트 이상)
jwt.secret=${JWT_SECRET:aW5zZXJ0LXlvdXItMjU2LWJpdC1iYXNlNjQtZW5jb2RlZC1zZWNyZXQta2V5LWhlcmU=}
jwt.access-token-validity=3600000
jwt.refresh-token-validity=1209600000
```

#### 3.1.3 Security Filter Chain 구성
**파일**: `Server/src/main/java/com/example/demo/config/SecurityConfig.java`

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Slf4j
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json;charset=UTF-8");
                    response.getWriter().write("{\"error\":\"Unauthorized\"}");
                }))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/users/**").authenticated()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("http://localhost:8081"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
```

#### 3.1.4 JWT 인증 필터
**파일**: `Server/src/main/java/com/example/demo/security/JwtAuthenticationFilter.java`

```java
@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain)
                                   throws ServletException, IOException {
        try {
            String token = extractTokenFromRequest(request);

            if (token != null && tokenProvider.validateToken(token)) {
                String userId = tokenProvider.getUserIdFromToken(token);
                List<String> roles = tokenProvider.getRolesFromToken(token);

                UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                        userId, null,
                        roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList())
                    );

                SecurityContextHolder.getContext().setAuthentication(auth);
                log.debug("JWT Authentication set for user: {}", userId);
            }
        } catch (Exception e) {
            log.error("JWT authentication failed", e);
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

**검증 방법**:
```bash
# Server 실행 후 인증 없이 접근 확인
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"id":"testuser","pw":"testpass"}'
# 401 Unauthorized 응답 확인 (아직 Phase 2 미완성이므로)
```

---

### Phase 2: Server 비즈니스 로직 변경 (2-3일)
**목표**: 기존 로그인/회원가입 로직에 보안 적용

#### 3.2.1 Entity 변경 (Role 추가)
**파일**: `Server/src/main/java/com/example/demo/user/entity/StdUser.java`

```java
@Entity
@Table(name="STD_USER")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "password")
public class StdUser {

    @Id
    @SequenceGenerator(name = "user_seq_gen", sequenceName = "USERS_SEQ", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_seq_gen")
    private Long seq;

    @Column(name = "ID", unique = true, nullable = false)
    private String id;

    @Column(name = "PASSWORD", nullable = false)
    private String password;

    @Column(name = "NAME", nullable = false)
    private String name;

    @Column(name = "EMAIL", nullable = false)
    private String email;

    @Column(name = "PERSONALNUMBER", nullable = false)
    private String personalNumber;

    // 추가 필드
    @Column(name = "ROLE")
    private String role = "ROLE_USER";

    @Column(name = "CREATED_AT")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "UPDATED_AT")
    private LocalDateTime updatedAt;

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    public UserDto toDto() {
        return new UserDto(seq, id, null, name, email, personalNumber, role);
        // password는 DTO에 포함 안 함 (보안)
    }
}
```

**마이그레이션**: Oracle DB에 컬럼 추가 (Hibernate ddl-auto=update로 자동)
```sql
-- 수동 확인용 쿼리
ALTER TABLE STD_USER ADD ROLE VARCHAR2(50) DEFAULT 'ROLE_USER';
ALTER TABLE STD_USER ADD CREATED_AT TIMESTAMP;
ALTER TABLE STD_USER ADD UPDATED_AT TIMESTAMP;
```

#### 3.2.2 회원가입 서비스 변경 (비밀번호 해싱)
**파일**: `Server/src/main/java/com/example/demo/user/service/SignupService.java`

```java
@Service
@Slf4j
public class SignupService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public SignupReply signup(SignupRequest request) {
        // 중복 체크
        if (userRepository.findById(request.getId()).isPresent()) {
            return new SignupReply(false, "이미 존재하는 사용자입니다", null);
        }

        // 비밀번호 해싱
        StdUser user = request.toStdUser();
        user.setPassword(passwordEncoder.encode(request.getPw()));
        user.setRole("ROLE_USER");
        user.setCreatedAt(LocalDateTime.now());

        StdUser savedUser = userRepository.save(user);
        log.info("User registered: {}", savedUser.getId());

        return new SignupReply(true, "회원가입 성공", savedUser.toDto());
    }
}
```

#### 3.2.3 인증 서비스 신규 작성
**파일**: `Server/src/main/java/com/example/demo/security/AuthService.java`

```java
@Service
@Slf4j
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    public LoginReply login(LoginRequest request) {
        Optional<StdUser> userOpt = userRepository.findById(request.getId());

        if (userOpt.isEmpty()) {
            log.warn("Login attempt with non-existent user: {}", request.getId());
            throw new RuntimeException("사용자를 찾을 수 없습니다");
        }

        StdUser user = userOpt.get();

        // 비밀번호 검증 (평문 vs 해시 비교)
        if (!passwordEncoder.matches(request.getPw(), user.getPassword())) {
            log.warn("Login failed - wrong password for user: {}", request.getId());
            throw new RuntimeException("비밀번호가 일치하지 않습니다");
        }

        // JWT 토큰 생성
        String accessToken = tokenProvider.generateAccessToken(
            user.getId(),
            Arrays.asList(user.getRole())
        );

        String refreshToken = tokenProvider.generateRefreshToken(user.getId());

        log.info("Login success: {}", user.getId());

        return LoginReply.builder()
            .ret(true)
            .msg("로그인 성공")
            .userDto(user.toDto())
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build();
    }
}
```

#### 3.2.4 LoginReply DTO 변경
**파일**: `Server/src/main/java/com/example/demo/user/dto/LoginReply.java`

```java
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class LoginReply {
    private Boolean ret;
    private String msg;
    private UserDto userDto;
    private String accessToken;  // 추가
    private String refreshToken; // 추가
}
```

#### 3.2.5 AuthController 신규 작성
**파일**: `Server/src/main/java/com/example/demo/security/AuthController.java`

```java
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private SignupService signupService;

    @PostMapping("/login")
    public ResponseEntity<LoginReply> login(@Valid @RequestBody LoginRequest request) {
        try {
            LoginReply reply = authService.login(request);
            return ResponseEntity.ok(reply);
        } catch (RuntimeException e) {
            log.error("Login failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new LoginReply(false, e.getMessage(), null, null, null));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<SignupReply> signup(@Valid @RequestBody SignupRequest request) {
        try {
            SignupReply reply = signupService.signup(request);
            return ResponseEntity.ok(reply);
        } catch (RuntimeException e) {
            log.error("Signup failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new SignupReply(false, e.getMessage(), null));
        }
    }
}
```

#### 3.2.6 기존 컨트롤러 제거/수정
- **삭제**: `Server/src/main/java/com/example/demo/user/controller/LoginController.java`
- **삭제**: `Server/src/main/java/com/example/demo/user/service/LoginService.java`

**검증 방법**:
```bash
# 1. 회원가입 (비밀번호 해싱 확인)
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "id":"testuser",
    "pw":"testpass123",
    "name":"테스트",
    "email":"test@test.com",
    "personalNumber":"900101-1234567"
  }'

# 2. DB 확인 (SQLPlus 또는 DBeaver)
SELECT ID, PASSWORD, ROLE FROM STD_USER WHERE ID='testuser';
# PASSWORD가 $2a$10$... 형태의 BCrypt 해시인지 확인

# 3. 로그인 (JWT 토큰 발급 확인)
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"id":"testuser","pw":"testpass123"}'
# 응답에 accessToken, refreshToken 포함 확인
```

---

### Phase 3: Client 토큰 관리 구현 (2일)
**목표**: Client에서 JWT 토큰 저장 및 자동 전달

#### 3.3.1 Client DTO 동기화
**파일**: `Client/src/main/java/com/example/demo/dto/LoginReply.java`

```java
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LoginReply {
    private Boolean ret;
    private String msg;
    private UserDto userDto;
    private String accessToken;  // 추가
    private String refreshToken; // 추가
}
```

#### 3.3.2 JWT 토큰 저장소 구현
**파일**: `Client/src/main/java/com/example/demo/Service/JwtTokenStore.java`

```java
@Service
@Slf4j
public class JwtTokenStore {

    private static final String ACCESS_TOKEN_KEY = "jwt_access_token";
    private static final String REFRESH_TOKEN_KEY = "jwt_refresh_token";
    private static final String USER_ID_KEY = "user_id";

    public void saveTokens(HttpSession session, String accessToken,
                          String refreshToken, String userId) {
        session.setAttribute(ACCESS_TOKEN_KEY, accessToken);
        session.setAttribute(REFRESH_TOKEN_KEY, refreshToken);
        session.setAttribute(USER_ID_KEY, userId);
        log.info("Tokens saved to session for user: {}", userId);
    }

    public String getAccessToken(HttpSession session) {
        return (String) session.getAttribute(ACCESS_TOKEN_KEY);
    }

    public String getRefreshToken(HttpSession session) {
        return (String) session.getAttribute(REFRESH_TOKEN_KEY);
    }

    public String getUserId(HttpSession session) {
        return (String) session.getAttribute(USER_ID_KEY);
    }

    public void clearTokens(HttpSession session) {
        session.removeAttribute(ACCESS_TOKEN_KEY);
        session.removeAttribute(REFRESH_TOKEN_KEY);
        session.removeAttribute(USER_ID_KEY);
        log.info("Tokens cleared from session");
    }

    public boolean isAuthenticated(HttpSession session) {
        return getAccessToken(session) != null;
    }
}
```

#### 3.3.3 RestTemplate Interceptor 구현
**파일**: `Client/src/main/java/com/example/demo/config/JwtRequestInterceptor.java`

```java
@Component
@Slf4j
public class JwtRequestInterceptor implements ClientHttpRequestInterceptor {

    @Autowired
    private HttpSession httpSession;

    @Autowired
    private JwtTokenStore tokenStore;

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body,
                                        ClientHttpRequestExecution execution)
                                        throws IOException {
        String token = tokenStore.getAccessToken(httpSession);

        if (token != null) {
            request.getHeaders().add("Authorization", "Bearer " + token);
            log.debug("JWT token added to Authorization header");
        }

        ClientHttpResponse response = execution.execute(request, body);

        // 401 처리 (추후 Refresh Token으로 자동 갱신 가능)
        if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            log.warn("Unauthorized response - token may have expired");
        }

        return response;
    }
}
```

#### 3.3.4 RestTemplateConfig 수정
**파일**: `Client/src/main/java/com/example/demo/config/RestTemplateConfig.java`

```java
@Configuration
@Slf4j
public class RestTemplateConfig {

    @Autowired
    private JwtRequestInterceptor jwtInterceptor;

    @Bean
    public RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate();

        // Interceptor 추가
        List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
        interceptors.add(jwtInterceptor);
        restTemplate.setInterceptors(interceptors);

        return restTemplate;
    }
}
```

#### 3.3.5 LoginService 수정
**파일**: `Client/src/main/java/com/example/demo/Service/LoginService.java`

```java
@Service
@Slf4j
public class LoginService {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private JwtTokenStore tokenStore;

    @Value("${server.api.url}")
    private String serverApiUrl;

    public LoginReply loginToServer(LoginRequest request, HttpSession session) {
        String url = serverApiUrl + "/api/auth/login";
        log.info("Calling REST API: {}", url);

        try {
            LoginReply reply = restTemplate.postForObject(url, request, LoginReply.class);

            if (reply == null) {
                throw new RuntimeException("Server에서 응답이 없습니다");
            }

            if (reply.getRet()) {
                // 토큰 저장
                tokenStore.saveTokens(
                    session,
                    reply.getAccessToken(),
                    reply.getRefreshToken(),
                    reply.getUserDto().getId()
                );
                log.info("Login success, tokens saved to session");
            }

            return reply;
        } catch (HttpClientErrorException e) {
            log.error("HTTP Error: {} - {}", e.getStatusCode(), e.getMessage());
            throw new RuntimeException("로그인 실패: " + e.getStatusCode());
        } catch (Exception e) {
            log.error("Login error", e);
            throw new RuntimeException("로그인 처리 중 오류 발생: " + e.getMessage());
        }
    }

    public void logout(HttpSession session) {
        tokenStore.clearTokens(session);
        log.info("Logout success");
    }
}
```

#### 3.3.6 LoginController 수정
**파일**: `Client/src/main/java/com/example/demo/controller/LoginController.java`

```java
@Controller
@Slf4j
public class LoginController {

    @Autowired
    private LoginService loginService;

    @Autowired
    private JwtTokenStore tokenStore;

    @GetMapping("/Login")
    public String accessLogin(HttpSession session, Model model) {
        // 이미 로그인 상태면 홈으로 리다이렉트
        if (tokenStore.isAuthenticated(session)) {
            return "redirect:/Home";
        }
        return "Login";
    }

    @PostMapping("/Login/UserAccount")
    public String tryLogin(@Valid @ModelAttribute LoginRequest userAccount,
                          BindingResult bindingResult,
                          HttpSession session,
                          Model model) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("Popup", "올바른 정보를 입력해주세요.");
            return "Login";
        }

        try {
            LoginReply reply = loginService.loginToServer(userAccount, session);

            if (!reply.getRet()) {
                model.addAttribute("Popup", "로그인 실패: " + reply.getMsg());
                return "Login";
            }

            log.info("Login success for user: {}", reply.getUserDto().getId());
            return "redirect:/Home";

        } catch (RuntimeException e) {
            model.addAttribute("Popup", "로그인 실패: " + e.getMessage());
            return "Login";
        }
    }

    @GetMapping("/Logout")
    public String logout(HttpSession session) {
        loginService.logout(session);
        return "redirect:/Login";
    }
}
```

**검증 방법**:
```bash
# 1. Client 실행 후 브라우저에서 테스트
# http://localhost:8081/Login
# 로그인 후 개발자 도구 → Application → Cookies 확인 (JSESSIONID)

# 2. 로그 확인
# Client 로그에서 "tokens saved to session" 메시지 확인
```

---

### Phase 4: 보호된 API 연동 (2일)
**목표**: 인증이 필요한 API 생성 및 Client 연동

#### 3.4.1 Server - 보호된 UserController 생성
**파일**: `Server/src/main/java/com/example/demo/user/controller/UserController.java`

```java
@RestController
@RequestMapping("/api/users")
@Slf4j
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser() {
        // SecurityContext에서 현재 사용자 정보 추출
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String userId = (String) auth.getPrincipal();

        Optional<StdUser> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        log.info("Fetched user info: {}", userId);
        return ResponseEntity.ok(userOpt.get().toDto());
    }

    @PutMapping("/me")
    public ResponseEntity<UserDto> updateCurrentUser(
            @Valid @RequestBody UserUpdateRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String userId = (String) auth.getPrincipal();

        Optional<StdUser> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        StdUser user = userOpt.get();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setUpdatedAt(LocalDateTime.now());

        StdUser updated = userRepository.save(user);
        log.info("User updated: {}", userId);

        return ResponseEntity.ok(updated.toDto());
    }
}
```

**파일**: `Server/src/main/java/com/example/demo/user/dto/UserUpdateRequest.java` (신규)
```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserUpdateRequest {
    @NotBlank(message = "이름을 입력해주세요")
    private String name;

    @NotBlank(message = "이메일을 입력해주세요")
    @Email(message = "올바른 이메일 형식이 아닙니다")
    private String email;
}
```

#### 3.4.2 Client - Home 페이지 생성
**파일**: `Client/src/main/java/com/example/demo/controller/HomeController.java`

```java
@Controller
@Slf4j
public class HomeController {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private JwtTokenStore tokenStore;

    @Value("${server.api.url}")
    private String serverApiUrl;

    @GetMapping("/Home")
    public String home(HttpSession session, Model model) {
        if (!tokenStore.isAuthenticated(session)) {
            return "redirect:/Login";
        }

        try {
            // Server에서 현재 사용자 정보 조회 (JWT로 인증)
            String url = serverApiUrl + "/api/users/me";
            UserDto user = restTemplate.getForObject(url, UserDto.class);

            model.addAttribute("user", user);
            return "Home";

        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                log.warn("Unauthorized access - redirecting to login");
                tokenStore.clearTokens(session);
                return "redirect:/Login";
            }
            log.error("Failed to fetch user info: {}", e.getMessage());
            model.addAttribute("error", "사용자 정보를 불러올 수 없습니다");
            return "Home";
        } catch (Exception e) {
            log.error("Error occurred", e);
            model.addAttribute("error", "오류가 발생했습니다");
            return "Home";
        }
    }
}
```

**파일**: `Client/src/main/resources/templates/Home.mustache`
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>홈</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .user-info { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .user-info p { margin: 10px 0; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>환영합니다, {{user.name}}님!</h1>

        {{#error}}
            <div style="color: red; padding: 10px; background: #ffe0e0; border-radius: 5px;">
                {{error}}
            </div>
        {{/error}}

        <div class="user-info">
            <p><strong>ID:</strong> {{user.id}}</p>
            <p><strong>이메일:</strong> {{user.email}}</p>
            <p><strong>권한:</strong> {{user.role}}</p>
        </div>

        <br/>
        <a href="/Logout">로그아웃</a>
    </div>
</body>
</html>
```

**검증 방법**:
```bash
# 1. 브라우저에서 로그인 후 /Home 접근
# 사용자 정보가 표시되는지 확인

# 2. Authorization 헤더 확인 (브라우저 Network 탭)
# Request Headers에 Authorization: Bearer eyJhbGc... 포함 확인

# 3. 토큰 없이 직접 접근 테스트
curl -X GET http://localhost:8080/api/users/me
# 401 Unauthorized 응답 확인

# 4. 토큰 포함 접근 테스트
TOKEN="로그인_시_받은_토큰"
curl -X GET http://localhost:8080/api/users/me \
  -H "Authorization: Bearer $TOKEN"
# 사용자 정보 JSON 응답 확인
```

---

### Phase 5: 고급 기능 및 운영 준비 (3일)
**목표**: Refresh Token, 에러 처리, 로깅, 모니터링

#### 3.5.1 Refresh Token 엔드포인트
**파일**: `Server/src/main/java/com/example/demo/security/AuthController.java` (추가)

```java
@PostMapping("/refresh")
public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
    try {
        String refreshToken = request.getRefreshToken();

        if (!tokenProvider.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new TokenRefreshResponse(false, "Invalid refresh token", null));
        }

        String userId = tokenProvider.getUserIdFromToken(refreshToken);

        // 새 Access Token 발급
        Optional<StdUser> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        StdUser user = userOpt.get();
        String newAccessToken = tokenProvider.generateAccessToken(
            user.getId(),
            Arrays.asList(user.getRole())
        );

        log.info("Token refreshed for user: {}", userId);

        return ResponseEntity.ok(
            new TokenRefreshResponse(true, "Token refreshed", newAccessToken)
        );

    } catch (Exception e) {
        log.error("Token refresh failed", e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(new TokenRefreshResponse(false, e.getMessage(), null));
    }
}
```

**파일**: `Server/src/main/java/com/example/demo/security/dto/TokenRefreshRequest.java`
```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TokenRefreshRequest {
    private String refreshToken;
}

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TokenRefreshResponse {
    private Boolean success;
    private String message;
    private String accessToken;
}
```

#### 3.5.2 환경변수 분리 (운영 준비)
**파일**: `Server/src/main/resources/application-prod.properties` (신규)

```properties
# 운영 환경 설정
spring.jpa.hibernate.ddl-auto=validate
spring.jpa.show-sql=false
logging.level.root=WARN
logging.level.com.example.demo.security=INFO

# JWT Secret (환경변수에서 주입)
jwt.secret=${JWT_SECRET}

# DB 자격증명 (환경변수에서 주입)
spring.datasource.username=${DB_USERNAME}
spring.datasource.password=${DB_PASSWORD}
```

**실행 스크립트**: `Server/start-prod.sh`
```bash
#!/bin/bash
export JWT_SECRET="your-production-secret-key-min-256-bits-base64-encoded"
export DB_USERNAME="app_user"
export DB_PASSWORD="StrongPassword!23"

./gradlew bootRun --args='--spring.profiles.active=prod'
```

#### 3.5.3 보안 로깅 강화
**파일**: `Server/src/main/resources/logback-spring.xml` (신규)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <appender name="SECURITY_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/security.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/security.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <logger name="com.example.demo.security" level="INFO" additivity="false">
        <appender-ref ref="SECURITY_FILE" />
        <appender-ref ref="CONSOLE" />
    </logger>

    <root level="INFO">
        <appender-ref ref="CONSOLE" />
    </root>
</configuration>
```

**검증 방법**:
```bash
# 1. 보안 로그 파일 생성 확인
tail -f Server/logs/security.log
# 로그인/로그아웃/토큰 발급 이벤트 기록 확인

# 2. 환경변수 테스트
JWT_SECRET=test-secret-base64-encoded ./gradlew bootRun
# 애플리케이션 시작 시 환경변수 적용 확인
```

---

## 4. 주의사항 및 Best Practices

### 4.1 보안 주의사항

#### 🔐 Critical
1. **JWT Secret 관리**
   - 최소 256비트 랜덤 문자열 사용
   - Base64 인코딩 필수
   - 절대 Git에 커밋 금지 (`.gitignore`에 추가)
   - 운영 환경에서 환경변수로 주입

   ```bash
   # 256비트 Secret 생성
   openssl rand -base64 32
   ```

2. **비밀번호 정책**
   - 최소 8자 이상, 대소문자/숫자/특수문자 조합
   - 회원가입 시 클라이언트/서버 양쪽 검증
   - 주기적 변경 정책 고려 (90일)

3. **HTTPS 적용**
   - 운영 환경에서 필수 (Let's Encrypt 무료 인증서)
   - HTTP → HTTPS 자동 리다이렉트 설정

#### ⚠️ Important
1. **토큰 만료 시간**
   - Access Token: 1시간 (짧을수록 안전)
   - Refresh Token: 2주 (적절한 균형)

2. **CORS 설정**
   - 운영 환경에서 와일드카드(`*`) 사용 금지
   - 명시적인 도메인만 허용

3. **에러 메시지**
   - 클라이언트에 상세 스택 트레이스 노출 금지
   - 로그인 실패 시 상세한 이유 공개 금지 (사용자 정보 보호)

### 4.2 개발 주의사항

#### 데이터베이스 마이그레이션
1. **기존 사용자 처리**
   - 평문 비밀번호를 가진 기존 사용자 처리 필요
   - 마이그레이션 스크립트 작성:
   ```java
   @Component
   public class PasswordMigrationRunner implements CommandLineRunner {
       @Autowired
       private UserRepository userRepository;

       @Autowired
       private PasswordEncoder passwordEncoder;

       @Override
       public void run(String... args) {
           List<StdUser> users = userRepository.findAll();

           for (StdUser user : users) {
               if (!user.getPassword().startsWith("$2a$")) { // BCrypt 아님
                   user.setPassword(passwordEncoder.encode(user.getPassword()));
                   userRepository.save(user);
               }
           }
       }
   }
   ```

2. **DDL 자동 생성 주의**
   - `spring.jpa.hibernate.ddl-auto=update`는 개발 전용
   - 운영 환경에서는 `validate` 사용
   - 수동 마이그레이션 스크립트 작성 권장

#### 테스트 전략
1. **통합 테스트 작성**
   ```java
   @SpringBootTest
   @AutoConfigureMockMvc
   public class AuthIntegrationTest {
       @Autowired
       private MockMvc mockMvc;

       @Test
       public void testLoginFlow() throws Exception {
           mockMvc.perform(post("/api/auth/login")
               .contentType(MediaType.APPLICATION_JSON)
               .content("{\"id\":\"test\",\"pw\":\"pass\"}"))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.accessToken").exists());
       }
   }
   ```

2. **JWT 테스트 도구**
   - https://jwt.io/ 에서 토큰 디코딩 검증
   - Postman에서 Authorization Bearer Token 테스트

---

## 5. 체크리스트

### Phase 1 완료 조건
- [ ] Server `build.gradle`에 Spring Security + JWT 의존성 추가
- [ ] `JwtTokenProvider` 구현 및 토큰 생성/검증 테스트
- [ ] `SecurityConfig` 작성 및 `/api/auth/**` 접근 허용 확인
- [ ] `JwtAuthenticationFilter` 작동 확인 (Authorization 헤더 파싱)
- [ ] CORS 설정 검증 (Client:8081 → Server:8080)

### Phase 2 완료 조건
- [ ] `StdUser` entity에 `role`, `createdAt` 컬럼 추가
- [ ] Oracle DB에 컬럼 추가 확인 (`SELECT * FROM STD_USER`)
- [ ] `SignupService`에서 BCrypt 해싱 확인 (DB password 필드 검증)
- [ ] `AuthService.login()` 정상 작동 (토큰 발급 확인)
- [ ] `LoginReply`에 `accessToken`, `refreshToken` 필드 추가
- [ ] 기존 `LoginController`/`LoginService` 제거

### Phase 3 완료 조건
- [ ] Client `LoginReply` DTO 동기화
- [ ] `JwtTokenStore` 구현 및 세션 저장 테스트
- [ ] `JwtRequestInterceptor` 작동 확인 (Authorization 헤더 자동 주입)
- [ ] `LoginService.loginToServer()` 토큰 저장 확인
- [ ] 브라우저 세션에서 토큰 확인 (개발자 도구)

### Phase 4 완료 조건
- [ ] Server `UserController.getCurrentUser()` 인증 필요 확인
- [ ] Client `/Home` 페이지에서 사용자 정보 표시
- [ ] 토큰 없이 접근 시 401 에러 확인
- [ ] 로그아웃 시 세션 초기화 확인

### Phase 5 완료 조건
- [ ] Refresh Token 엔드포인트 작동 확인
- [ ] 보안 로그 파일 생성 확인 (`logs/security.log`)
- [ ] 환경변수 주입 테스트 (JWT_SECRET 등)
- [ ] `application-prod.properties` 작성

---

## 6. 마이그레이션 일정

| 주차 | Phase | 작업 시간 | 완료 기준 |
|------|-------|---------|---------|
| 1주차 월-수 | Phase 1 | 2-3일 | Server JWT 인프라 완성 |
| 1주차 목-금 | Phase 2 | 2-3일 | 로그인/회원가입 보안 적용 |
| 2주차 월-화 | Phase 3 | 2일 | Client 토큰 관리 완성 |
| 2주차 수-목 | Phase 4 | 2일 | 보호된 API 연동 완료 |
| 2주차 금-주말 | Phase 5 | 3일 | 운영 준비 완료 |
| **총 기간** | **5 Phases** | **11-14일** | **완전한 인증 시스템** |

---

## 참고 자료

### 공식 문서
- Spring Security Reference: https://docs.spring.io/spring-security/reference/index.html
- JJWT Library: https://github.com/jwtk/jjwt
- Spring Boot Security Auto-configuration: https://docs.spring.io/spring-boot/reference/web/spring-security.html

### 보안 가이드
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- JWT Best Practices: https://tools.ietf.org/html/rfc8725

이 계획서는 현재 프로젝트의 클라이언트-서버 분리 아키텍처에 최적화되어 있으며, 단계별로 안전하게 마이그레이션할 수 있도록 설계되었습니다. 각 Phase를 완료할 때마다 검증 단계를 거쳐 안정성을 확보하세요.
