package org.example.apigateway.routes;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

@Component
public class RouterValidator {

    AntPathMatcher antPathMatcher = new AntPathMatcher();

    // Open endpoints (no auth required) - match requirements
    public static final List<String> openAPIEndpoints = List.of(
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/refresh"
    );

    public Predicate<ServerHttpRequest> isSecured = req -> {
        String path = req.getURI().getPath();
        return openAPIEndpoints.stream().noneMatch(uri -> antPathMatcher.match(uri, path));
    };

    public List<String> getRequiredRoles(String path) {
        return Collections.emptyList();
    }
}
