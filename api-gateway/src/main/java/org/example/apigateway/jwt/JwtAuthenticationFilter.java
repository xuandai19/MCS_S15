package org.example.apigateway.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.example.apigateway.routes.RouterValidator;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtils jwtUtils;
    private final RouterValidator routerValidator;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // Public paths → skip JWT check
        if (!routerValidator.isSecured.test(request)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        try {
            if (!jwtUtils.validationToken(token)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            Claims claims = jwtUtils.extractAllClaims(token);
            String jti = claims.get("jti", String.class);

            // Check blacklist on Redis
            if (jti != null) {
                return redisTemplate.hasKey("blacklist:" + jti)
                        .flatMap(isBlacklisted -> {
                            if (Boolean.TRUE.equals(isBlacklisted)) {
                                return onError(exchange, HttpStatus.UNAUTHORIZED);
                            }
                            return continueFilter(exchange, chain, claims, token);
                        });
            }

            return continueFilter(exchange, chain, claims, token);
        } catch (Exception e) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> continueFilter(ServerWebExchange exchange, GatewayFilterChain chain,
                                      Claims claims, String token) {
        try {
            // Extract permissions array from token (final requirement style)
            Object permsObj = claims.get("permissions");
            List<?> permissionsList = permsObj instanceof List ? (List<?>) permsObj : Collections.emptyList();
            String permissionsJson = objectMapper.writeValueAsString(permissionsList);

            // Also keep role for compatibility if present
            Object roleObj = claims.get("role");
            String roleStr = roleObj != null ? roleObj.toString() : "";

            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-User-Permissions", permissionsJson)
                    .header("X-User-Role", roleStr)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        } catch (Exception e) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
