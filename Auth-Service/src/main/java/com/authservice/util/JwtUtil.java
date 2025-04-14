package com.authservice.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.JwtException;
import java.security.Key; // Correct import for Key class
import java.util.Date;

import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    // This will generate a 256-bit key for HMACSHA256
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // Generate token with 10 hours of expiration
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours
                .signWith(SECRET_KEY)
                .compact();
    }

    // Validate token and retrieve the username (subject)
    public String validateTokenAndRetrieveSubject(String token) throws JwtException {
        try {
            return Jwts.parserBuilder() // Updated to parserBuilder() in latest versions
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (JwtException e) {
            throw new JwtException("Invalid or expired JWT token");
        }
    }
}
