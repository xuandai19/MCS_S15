package org.example.identityservice.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.example.identityservice.models.entities.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.jwt.access-token-expiration}")
    private Long accessTokenExpiration;

    public Key getSignKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate Access Token:
     * - sub = username
     * - role = primary role (STUDENT / INSTRUCTOR)
     * - permissions = detailed list e.g. ["COURSE_READ", "COURSE_WRITE"]
     * - jti = unique id for blacklist
     */
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());

        List<String> roleNames = user.getRoles().stream()
                .map(r -> r.getRoleName().name())
                .collect(Collectors.toList());

        // Primary role claim (as per early requirements)
        String primaryRole = roleNames.isEmpty() ? "STUDENT" : roleNames.get(0);
        claims.put("role", primaryRole);

        // Detailed permissions based on role (final requirement)
        List<String> permissions = new ArrayList<>();
        if (roleNames.contains("INSTRUCTOR") || roleNames.contains("ADMIN")) {
            permissions.add("COURSE_READ");
            permissions.add("COURSE_WRITE");
        } else if (roleNames.contains("STUDENT")) {
            permissions.add("COURSE_READ");
        }
        // ADMIN gets all
        if (roleNames.contains("ADMIN")) {
            permissions.add("COURSE_READ");
            permissions.add("COURSE_WRITE");
        }
        claims.put("permissions", permissions.stream().distinct().collect(Collectors.toList()));

        // jti required
        claims.put("jti", UUID.randomUUID().toString());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractJti(String token) {
        return extractClaim(token, claims -> claims.get("jti", String.class));
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
