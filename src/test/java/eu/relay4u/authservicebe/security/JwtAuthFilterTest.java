package eu.relay4u.authservicebe.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock JwtUtil jwtUtil;
    @Mock UserDetailsService userDetailsService;
    @Mock HttpServletRequest request;
    @Mock HttpServletResponse response;
    @Mock FilterChain filterChain;
    @Mock Claims claims;
    @Mock UserDetails userDetails;

    @InjectMocks JwtAuthFilter jwtAuthFilter;

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    // --- Happy path ---

    @Test
    void doFilterInternal_withValidToken_setsAuthentication() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Bearer valid-token");
        when(jwtUtil.extractAllClaims("valid-token")).thenReturn(claims);
        when(jwtUtil.isTokenExpired(claims)).thenReturn(false);
        when(jwtUtil.extractEmail(claims)).thenReturn("jane@example.com");
        when(userDetailsService.loadUserByUsername("jane@example.com")).thenReturn(userDetails);
        when(userDetails.isAccountNonLocked()).thenReturn(true);
        when(userDetails.isEnabled()).thenReturn(true);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isSameAs(userDetails);
        verify(filterChain).doFilter(request, response);
    }

    // --- Sad path ---

    @Test
    void doFilterInternal_withoutAuthorizationHeader_doesNotSetAuthentication() throws Exception {
        when(request.getHeader("Authorization")).thenReturn(null);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void doFilterInternal_withNonBearerHeader_doesNotSetAuthentication() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withInvalidToken_doesNotSetAuthentication() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Bearer garbage-token");
        when(jwtUtil.extractAllClaims("garbage-token")).thenThrow(new JwtException("bad token"));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withExpiredToken_doesNotSetAuthentication() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Bearer expired-token");
        when(jwtUtil.extractAllClaims("expired-token")).thenReturn(claims);
        when(jwtUtil.isTokenExpired(claims)).thenReturn(true);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_withLockedAccount_doesNotSetAuthentication() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Bearer valid-token");
        when(jwtUtil.extractAllClaims("valid-token")).thenReturn(claims);
        when(jwtUtil.isTokenExpired(claims)).thenReturn(false);
        when(jwtUtil.extractEmail(claims)).thenReturn("jane@example.com");
        when(userDetailsService.loadUserByUsername("jane@example.com")).thenReturn(userDetails);
        when(userDetails.isAccountNonLocked()).thenReturn(false);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }
}
