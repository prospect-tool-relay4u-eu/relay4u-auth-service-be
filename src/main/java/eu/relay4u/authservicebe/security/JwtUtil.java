package eu.relay4u.authservicebe.security;

import eu.relay4u.authservicebe.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;

@Component
@Getter
public class JwtUtil {

    public static final String KEY_ID = "auth-key-1";

    @Value("${jwt.expiration.in.hours}")
    private Long expirationInHours;

    @Value("${jwt.issuer}")
    private String issuer;

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public JwtUtil(@Value("${jwt.private-key:}") String privateKeyPem) {
        if (privateKeyPem == null || privateKeyPem.isBlank()) {
            KeyPair keyPair = generateEphemeralKeyPair();
            this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
            this.publicKey = (RSAPublicKey) keyPair.getPublic();
        } else {
            this.privateKey = parsePrivateKey(privateKeyPem);
            this.publicKey = derivePublicKey(this.privateKey);
        }
    }

    public String generateToken(User user) {
        return Jwts.builder()
                .header().add("kid", KEY_ID).and()
                .subject(String.valueOf(user.getId()))
                .claim("email", user.getEmail())
                .claim("name", user.getName())
                .issuer(issuer)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(
                        new Date(System.currentTimeMillis()
                                + expirationInHours
                                * 60 * 60 * 1000))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public String extractEmail(Claims claims) {
        return claims.get("email", String.class);
    }

    public Long extractUserId(Claims claims) {
        return Long.valueOf(claims.getSubject());
    }

    private RSAPrivateKey parsePrivateKey(String pem) {
        String normalized = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(normalized);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new IllegalStateException("Invalid RSA private key configured in jwt.private-key", e);
        }
    }

    private RSAPublicKey derivePublicKey(RSAPrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey crtKey)) {
            throw new IllegalStateException("RSA private key must be a PKCS8 CRT key to derive its public key");
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
            return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to derive RSA public key from configured private key", e);
        }
    }

    private KeyPair generateEphemeralKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not available", e);
        }
    }
}
