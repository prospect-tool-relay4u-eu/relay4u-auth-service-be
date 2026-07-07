package eu.relay4u.authservicebe.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
@Getter
public class JwtUtil {

    @Value("${jwt.expiration.in.hours}")
    private Long expirationInHours;

    private final SecretKey secret;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        this.secret = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateToken(String name) {
        return Jwts.builder()
                .subject(name)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(
                        new Date(System.currentTimeMillis()
                                + expirationInHours
                                * 60 * 60 * 1000))
                .signWith(secret)
                .compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(secret)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public String extractEmail(Claims claims) {
        return claims.getSubject();
    }
}