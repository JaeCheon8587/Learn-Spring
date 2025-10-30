//💡 실무 포인트
//@Component: Spring Bean으로 등록하여 다른 곳에서 주입받아 사용
//HMAC SHA-256: 업계 표준 서명 알고리즘
//Claims: JWT Payload에 담긴 사용자 정보 (sub, iat, exp 등)

package com.example.demo.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;


@Component
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration-ms}")
    private long jwtExpirationMs;

    private SecretKey getSigningKey(){
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String userId){
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }
    
    public String getUserIdFromToken(String token){
        Claims claims = Jwts.parser()
                            .verifyWith(getSigningKey())
                            .build()
                            .parseSignedClaims(token)
                            .getPayload();

        return claims.getSubject();
    }

    public boolean validateToken(String token){
        try{
            Jwts.parser()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
            return true;
        }
        catch(MalformedJwtException ex){
            System.err.println("Malformed JWT token: " + ex.getMessage());
        }
        catch(ExpiredJwtException ex){
            System.err.println("Expired JWT token: " + ex.getMessage());
        }
        catch(UnsupportedJwtException ex){
            System.err.println("Unsupported JWT token: " + ex.getMessage());
        }
        catch(IllegalArgumentException ex){
            System.err.println("JWT claims string is empty: " + ex.getMessage());
        }
        catch(Exception ex){
            System.err.println("Invalid JWT token: " + ex.getMessage());
        }

        return false;
    }
}
