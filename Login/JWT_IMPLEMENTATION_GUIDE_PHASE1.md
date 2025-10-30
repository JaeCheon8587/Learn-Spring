# JWT 구현 가이드 - Phase 1: JWT 토큰 생성 및 발급

> **작성일**: 2025년
> **목표**: 로그인 성공 시 JWT 토큰 생성 및 응답에 포함
> **예상 시간**: 1~2시간

---

## 📋 Phase 1 목표

- [x] Step 1: JWT 설정 추가 (application.properties)
- [x] Step 2: JwtTokenProvider 클래스 생성 (JWT 생성/검증 유틸리티)
- [ ] Step 3: LoginReply.java에 token 필드 추가
- [ ] Step 4: LoginService.java에서 JWT 토큰 생성 및 발급
- [ ] Step 5: 테스트 (Postman/curl)

---

## Step 1: JWT 설정 추가

### 📝 작업 파일
`Server/src/main/resources/application.properties`

### ✍️ 추가할 코드
파일 맨 아래에 추가:

```properties
# JWT 설정
jwt.secret=your-super-secret-key-min-32-characters-long-for-production-use
jwt.expiration=3600000
# 3600000ms = 1시간 (1000ms * 60초 * 60분)
```

### 💡 설명

#### jwt.secret (JWT 서명 키)
- **용도**: JWT 토큰의 서명(Signature) 생성에 사용
- **최소 길이**: 32자 (256비트)
- **보안**:
  - 개발: 예시 값 그대로 사용 가능
  - 운영: 반드시 환경변수로 관리 (`${JWT_SECRET}`)

#### jwt.expiration (토큰 만료 시간)
- **단위**: 밀리초(ms)
- **권장값**:
  - Access Token: 1시간 (3600000ms)
  - Refresh Token: 7~30일 (604800000~2592000000ms)

### ⚠️ 보안 주의사항

**개발 단계:**
```properties
jwt.secret=your-super-secret-key-min-32-characters-long-for-production-use
```

**운영 단계 (필수):**
```properties
jwt.secret=${JWT_SECRET}
jwt.expiration=${JWT_EXPIRATION:3600000}
```

**환경변수 설정:**
```bash
# Linux/Mac
export JWT_SECRET="랜덤으로-생성한-32자-이상의-문자열"

# Windows
set JWT_SECRET=랜덤으로-생성한-32자-이상의-문자열
```

**안전한 Secret Key 생성 방법:**

1. 온라인 생성기: https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx
2. 커맨드라인:
   ```bash
   openssl rand -base64 32
   ```
3. 자바 코드:
   ```java
   KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
   keyGen.init(256);
   SecretKey secretKey = keyGen.generateKey();
   String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
   ```

---

## Step 2: JwtTokenProvider 클래스 생성

### 📂 디렉토리 구조
```
Server/src/main/java/com/example/demo/
├── config/
│   └── SecurityConfig.java (기존)
├── security/  ← 새로 만들기
│   └── JwtTokenProvider.java  ← 새로 만들기
└── user/
```

### 📝 작업 파일 (새로 생성)
`Server/src/main/java/com/example/demo/security/JwtTokenProvider.java`

### ✍️ 전체 코드

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
 * 1. generateToken(): JWT 생성 (로그인 성공 시 호출)
 * 2. validateToken(): JWT 검증 (API 호출 시 자동 검증)
 * 3. getUserIdFromToken(): JWT에서 사용자 ID 추출
 */
@Component
public class JwtTokenProvider {

    // application.properties에서 주입받음
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    /**
     * SecretKey 생성 (HMAC SHA-256)
     *
     * 보안 요구사항:
     * - 최소 256비트 (32바이트) 길이
     * - 예측 불가능한 랜덤 문자열
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * JWT 토큰 생성
     *
     * @param userId 사용자 ID (Subject로 사용)
     * @return JWT 토큰 문자열 (예: eyJhbGciOiJIUzI1NiJ9.eyJzdWI...)
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
     * @return 사용자 ID (예: "user123")
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

### 🔍 코드 상세 설명

#### 1. `@Value` 어노테이션
```java
@Value("${jwt.secret}")
private String jwtSecret;
```
- `application.properties`에서 설정한 값을 자동으로 주입
- Spring이 런타임에 `jwt.secret` 값을 찾아서 `jwtSecret` 필드에 할당

#### 2. `getSigningKey()` 메서드
```java
private SecretKey getSigningKey() {
    byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
    return Keys.hmacShaKeyFor(keyBytes);
}
```
- Secret Key 문자열을 바이트 배열로 변환
- HMAC SHA-256 알고리즘용 SecretKey 객체 생성
- JWT 서명과 검증에 사용

#### 3. `generateToken()` 메서드
```java
return Jwts.builder()
        .setSubject(userId)           // Payload의 "sub" 클레임
        .setIssuedAt(now)             // Payload의 "iat" 클레임
        .setExpiration(expiryDate)    // Payload의 "exp" 클레임
        .signWith(getSigningKey())    // Signature 생성
        .compact();                   // 최종 토큰 문자열 생성
```

**생성되는 JWT 구조:**
```
Header.Payload.Signature
```

**실제 예시:**
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**디코딩된 내용 (https://jwt.io 에서 확인 가능):**
```json
// Header
{
  "alg": "HS256",
  "typ": "JWT"
}

// Payload
{
  "sub": "user123",
  "iat": 1700000000,
  "exp": 1700003600
}

// Signature (서명 - 검증용)
```

#### 4. `getUserIdFromToken()` 메서드
```java
Claims claims = Jwts.parserBuilder()
        .setSigningKey(getSigningKey())
        .build()
        .parseClaimsJws(token)
        .getBody();

return claims.getSubject();
```
- JWT 토큰을 파싱하여 Payload 추출
- `sub` 클레임에서 사용자 ID 반환
- Phase 2에서 인증 필터에서 사용됨

#### 5. `validateToken()` 메서드
```java
try {
    Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token);
    return true;
} catch (...) {
    return false;
}
```

**검증 항목:**
1. **서명 검증**: Secret Key로 서명이 올바른지 확인 (위변조 방지)
2. **만료 시간 검증**: 현재 시간이 `exp` 이전인지 확인
3. **형식 검증**: JWT 형식이 올바른지 확인

**예외 처리:**
- `MalformedJwtException`: 잘못된 JWT 형식
- `ExpiredJwtException`: 만료된 토큰
- `UnsupportedJwtException`: 지원하지 않는 JWT
- `IllegalArgumentException`: 빈 문자열

### ⚠️ 보안 주의사항

#### ❌ 절대 하지 말 것

```java
// Payload는 Base64로만 인코딩되어 있어 누구나 디코딩 가능!
return Jwts.builder()
        .setSubject(userId)
        .claim("password", user.getPassword())        // ❌ 비밀번호 노출!
        .claim("ssn", user.getSocialSecurityNumber()) // ❌ 주민번호 노출!
        .claim("creditCard", user.getCardNumber())    // ❌ 카드번호 노출!
        .signWith(getSigningKey())
        .compact();
```

#### ✅ 올바른 방법

```java
// 식별자만 저장
return Jwts.builder()
        .setSubject(userId)  // "user123" 같은 식별자만
        .signWith(getSigningKey())
        .compact();
```

**이유:**
- JWT의 Payload는 **암호화되지 않습니다**
- Base64 디코딩만으로 누구나 내용을 볼 수 있습니다
- 민감한 정보는 절대 포함하지 말 것!

### 💡 JWT 구조 이해

```
eyJhbGciOiJIUzI1NiJ9  ←─ Header (Base64)
    .
eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9  ←─ Payload (Base64)
    .
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ←─ Signature (암호화)
```

1. **Header**: 알고리즘 정보 (HS256)
2. **Payload**: 사용자 데이터 (sub, iat, exp) - **암호화 안 됨!**
3. **Signature**: 위변조 방지 서명 - **암호화됨**

---

## 🔧 선택사항: Configuration Processor 추가

### 문제 상황
IDE에서 다음과 같은 경고가 표시될 수 있습니다:
```properties
jwt.secret=...  ⚠️ Cannot resolve configuration property 'jwt.secret'
jwt.expiration=...  ⚠️ Cannot resolve configuration property 'jwt.expiration'
```

### 원인
Spring Boot Configuration Processor가 없어서 IDE가 사용자 정의 속성을 인식하지 못함

### 해결 방법 (선택사항)

**Server/build.gradle**의 `dependencies` 블록에 추가:

```gradle
dependencies {
    // 기존 의존성들...

    // ✅ 이 줄을 추가
    annotationProcessor 'org.springframework.boot:spring-boot-configuration-processor'

    // 나머지 의존성들...
}
```

**추가 후 실행:**
```bash
cd Server
./gradlew clean build
```

**효과:**
- ✅ IDE 경고 제거
- ✅ 자동완성 지원
- ✅ 오타 감지
- ✅ 타입 검증

### Configuration Processor란?

**역할:** 어노테이션(`@Value`) ↔ 설정 파일(`application.properties`) 링커

**동작 과정:**
```
1. 컴파일 시점
   ↓
2. @Value 어노테이션 스캔
   ↓
3. 메타데이터 파일 생성
   (spring-configuration-metadata.json)
   ↓
4. IDE가 메타데이터 읽기
   ↓
5. 자동완성, 경고 제거, 타입 체크
```

**메타데이터 예시:**
```json
{
  "properties": [
    {
      "name": "jwt.secret",
      "type": "java.lang.String",
      "sourceType": "com.example.demo.security.JwtTokenProvider"
    }
  ]
}
```

**중요:** 런타임 동작에는 영향 없음! 개발 편의성만 향상.

---

## ✅ Step 1~2 완료 체크리스트

- [ ] `application.properties`에 `jwt.secret`, `jwt.expiration` 추가
- [ ] `Server/src/main/java/com/example/demo/security/` 폴더 생성
- [ ] `JwtTokenProvider.java` 파일 생성 및 코드 작성
- [ ] Import 문 정리 (IDE에서 Ctrl+Shift+O 또는 Cmd+Shift+O)
- [ ] 컴파일 에러 없음 확인
- [ ] (선택) Configuration Processor 추가하여 IDE 경고 제거

---

## 🚀 다음 단계 예고

### Step 3: LoginReply.java 수정
- `token` 필드 추가
- 로그인 응답에 JWT 토큰 포함

### Step 4: LoginService.java 수정
- `JwtTokenProvider` 주입
- 로그인 성공 시 JWT 토큰 생성
- `LoginReply`에 토큰 포함하여 반환

### Step 5: 테스트
```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"id":"testuser","pw":"password123"}'

# 응답에 token 필드 확인
{
  "ret": true,
  "msg": "로그인 성공",
  "userAccount": {...},
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

---

## 📚 참고 자료

- [JWT.io](https://jwt.io) - JWT 디코더 및 문서
- [JJWT GitHub](https://github.com/jwtk/jjwt) - Java JWT 라이브러리
- [Spring Boot Configuration Metadata](https://docs.spring.io/spring-boot/docs/current/reference/html/configuration-metadata.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

**작성자 노트:** 이 문서는 학습 과정을 기록한 것으로, Step 3~5는 별도 문서로 작성 예정.
