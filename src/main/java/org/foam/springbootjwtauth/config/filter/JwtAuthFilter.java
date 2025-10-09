package org.foam.springbootjwtauth.config.filter;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.service.auth.JwtService;
import org.foam.springbootjwtauth.service.auth.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;

    @Autowired
    public JwtAuthFilter(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        logger.info("Executing JwtAuthFilter");
        String authHeader = request.getHeader("Authorization");
        logger.info("Authorization header in request: " + authHeader);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            logger.info("Token in request: " + token);
            try {
                String userName = jwtService.extractAllClaims(token).getSubject();
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (userName != null && authentication == null) {
                    User user = userService.loadUserByUsername(userName);
                    logger.info("User loaded with id:" + user.getId());
                    if (jwtService.validateAccessToken(token, user)) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                user, null, user.getAuthorities());
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        logger.info("Authenticated user: " + user.getUsername());
                    }
                }
            } catch (JwtException error) {
                // token validation failed, so do not authenticate
                logger.info("Token validation failed with JwtException: " + error.getMessage());
            }
        }
        logger.info("Finished executing JwtAuthFilter");

        filterChain.doFilter(request, response);
    }
}
