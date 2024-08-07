package com.security.jwt.service;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenService {

    public String generateToken(String clientId, String jwtSecret, String audience) {
        long now = System.currentTimeMillis();
        long expirationTime = now + 3600000; // Token expires in 1 hour

        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());

        return Jwts.builder()
                .setSubject(clientId)
                .setAudience(audience)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(expirationTime))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
