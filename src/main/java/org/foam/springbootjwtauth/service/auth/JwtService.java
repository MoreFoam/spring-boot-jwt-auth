package org.foam.springbootjwtauth.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.foam.springbootjwtauth.exception.auth.RefreshTokenNotFoundException;
import org.foam.springbootjwtauth.model.database.auth.RefreshToken;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.repository.auth.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;

@Service
public class JwtService {

    @Value("${spring-boot-jwt-auth.security.jwt.secret-key}")
    private String secretKey;

    @Value("${spring-boot-jwt-auth.security.jwt.expiration}")
    private long expiration;

    @Value("${spring-boot-jwt-auth.security.jwt.refresh-expiration}")
    private long refreshExpiration;

    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public JwtService(RefreshTokenRepository refreshTokenRepository, PasswordEncoder passwordEncoder) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("roles", user.getRoleNames());

        return createAccessToken(claims, user.getUsername());
    }

    public String generateRefreshToken(User user, Long refreshTokenId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", refreshTokenId);
        claims.put("userId", user.getId());
        claims.put("deviceId", UUID.randomUUID().toString());

        return createRefreshToken(claims, user.getUsername());
    }

    public Boolean validateAccessToken(String token, User user) {
        try {
            var claims = extractAllClaims(token);

            return claims.getSubject().equals(user.getUsername())
                    && !isTokenExpired(claims);
        } catch (JwtException e) { //
            return false;
        }
    }

    public Boolean validateRefreshToken(String token, User user) throws RefreshTokenNotFoundException {
        Claims claims = extractAllClaims(token);
        Optional<RefreshToken> refreshTokenOptional = refreshTokenRepository.findById(Long.valueOf(claims.get("id").toString()));

        if (refreshTokenOptional.isEmpty()) { // did not find token in db
            throw new RefreshTokenNotFoundException();
        }

        RefreshToken refreshToken = refreshTokenOptional.get();

        return !isTokenExpired(claims)
                && claims.getSubject().equals(user.getUsername())
                && refreshToken.getUserId().equals(user.getId())
                && refreshToken.getDeviceId().equals(claims.get("deviceId"))
                && passwordEncoder.matches(token, refreshToken.getToken());
    }

    public Boolean validateExpiredRefreshToken(String token, Claims claims, User user) {
        Optional<RefreshToken> refreshTokenOptional = refreshTokenRepository.findById(Long.valueOf(claims.get("id").toString()));

        if (refreshTokenOptional.isEmpty()) { // did not find token in db
            return false;
        }

        RefreshToken refreshToken = refreshTokenOptional.get();

        boolean subjectMatches = claims.getSubject().equals(user.getUsername());
        boolean userIdMatches = refreshToken.getUserId().equals(user.getId());
        boolean deviceIdMatches = refreshToken.getDeviceId().equals(claims.get("deviceId"));
        boolean tokenMatches = passwordEncoder.matches(token, refreshToken.getToken());

        return subjectMatches
                && userIdMatches
                && deviceIdMatches
                && tokenMatches;
    }

    private String createAccessToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    private String createRefreshToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);

        return Keys.hmacShaKeyFor(keyBytes);
    }

    private boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public Claims extractAllClaims(String token) throws JwtException {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token) // This verifies the token signature. If verification fails, JwtException is thrown
                .getPayload();
    }

    public void invalidateRefreshToken(Long id) {
        refreshTokenRepository.delete(
                refreshTokenRepository
                        .findById(id)
                        .orElseThrow(() -> new NoSuchElementException("Invalid refresh token")));
    }
}

