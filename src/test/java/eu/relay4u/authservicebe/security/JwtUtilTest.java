package eu.relay4u.authservicebe.security;

import eu.relay4u.authservicebe.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private User user;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil("");
        ReflectionTestUtils.setField(jwtUtil, "expirationInHours", 24L);
        ReflectionTestUtils.setField(jwtUtil, "issuer", "https://auth.relay4u.eu");

        user = new User();
        user.setId(42L);
        user.setEmail("jane@example.com");
        user.setName("Jane Doe");
    }

    // --- Happy path ---

    @Test
    void generateToken_thenExtractAllClaims_roundTripsUserData() {
        String token = jwtUtil.generateToken(user);

        Claims claims = jwtUtil.extractAllClaims(token);

        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.get("email", String.class)).isEqualTo("jane@example.com");
        assertThat(claims.get("name", String.class)).isEqualTo("Jane Doe");
        assertThat(claims.getIssuer()).isEqualTo("https://auth.relay4u.eu");
    }

    @Test
    void extractEmail_returnsEmailClaim() {
        String token = jwtUtil.generateToken(user);
        Claims claims = jwtUtil.extractAllClaims(token);

        assertThat(jwtUtil.extractEmail(claims)).isEqualTo("jane@example.com");
    }

    @Test
    void extractUserId_returnsSubjectAsLong() {
        String token = jwtUtil.generateToken(user);
        Claims claims = jwtUtil.extractAllClaims(token);

        assertThat(jwtUtil.extractUserId(claims)).isEqualTo(42L);
    }

    @Test
    void isTokenExpired_returnsFalse_forFutureExpiration() {
        Claims claims = Jwts.claims().expiration(new Date(System.currentTimeMillis() + 60_000)).build();

        assertThat(jwtUtil.isTokenExpired(claims)).isFalse();
    }

    @Test
    void constructor_withConfiguredPrivateKeyPem_derivesMatchingPublicKeyAndSignsTokens() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----";

        JwtUtil configuredJwtUtil = new JwtUtil(pem);
        ReflectionTestUtils.setField(configuredJwtUtil, "expirationInHours", 24L);
        ReflectionTestUtils.setField(configuredJwtUtil, "issuer", "https://auth.relay4u.eu");

        String token = configuredJwtUtil.generateToken(user);
        Claims claims = configuredJwtUtil.extractAllClaims(token);

        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(configuredJwtUtil.getPublicKey()).isEqualTo(keyPair.getPublic());
    }

    // --- Sad path / edge cases ---

    @Test
    void isTokenExpired_returnsTrue_forPastExpiration() {
        Claims claims = Jwts.claims().expiration(new Date(0)).build();

        assertThat(jwtUtil.isTokenExpired(claims)).isTrue();
    }

    @Test
    void constructor_withMalformedPrivateKeyPem_throwsIllegalStateException() {
        String bogusPem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getEncoder().encodeToString("not a real key".getBytes())
                + "\n-----END PRIVATE KEY-----";

        assertThatThrownBy(() -> new JwtUtil(bogusPem))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void extractAllClaims_withTokenSignedByDifferentKey_throwsJwtException() {
        JwtUtil otherJwtUtil = new JwtUtil("");
        ReflectionTestUtils.setField(otherJwtUtil, "expirationInHours", 24L);
        ReflectionTestUtils.setField(otherJwtUtil, "issuer", "https://auth.relay4u.eu");
        String token = otherJwtUtil.generateToken(user);

        assertThatThrownBy(() -> jwtUtil.extractAllClaims(token))
                .isInstanceOf(io.jsonwebtoken.JwtException.class);
    }
}
