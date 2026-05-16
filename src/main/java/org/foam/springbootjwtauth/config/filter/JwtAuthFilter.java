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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtService jwtService;
    private final UserService userService;

    @Autowired
    public JwtAuthFilter(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String requestPath = request.getRequestURI();
        String requestMethod = request.getMethod();
        String authHeader = request.getHeader("Authorization");

        logger.debug("JwtAuthFilter processing {} {}", requestMethod, requestPath);

        if (authHeader == null) {
            logger.debug("No Authorization header present for {} {}", requestMethod, requestPath);
        } else if (!authHeader.startsWith("Bearer ")) {
            logger.debug("Authorization header is present but is not a Bearer token for {} {}", requestMethod, requestPath);
        } else {
            String token = authHeader.substring(7);

            try {
                String userName = jwtService.extractAllClaims(token).getSubject();
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                logger.debug(
                        "Bearer token parsed for {} {} with subject [{}]; existing authentication present: {}",
                        requestMethod,
                        requestPath,
                        userName,
                        authentication != null);

                if (userName != null && authentication == null) {
                    User user = userService.loadUserByUsername(userName);

                    if (jwtService.validateAccessToken(token, user)) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                user, null, user.getAuthorities());
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        logger.debug(
                                "Authenticated request {} {} for user [{}] with id [{}] and authorities {}",
                                requestMethod,
                                requestPath,
                                user.getUsername(),
                                user.getId(),
                                user.getAuthorities());
                    } else {
                        logger.debug(
                                "Bearer token failed validation for {} {} with subject [{}]",
                                requestMethod,
                                requestPath,
                                userName);
                    }
                } else if (userName == null) {
                    logger.debug("Bearer token did not contain a subject for {} {}", requestMethod, requestPath);
                } else {
                    logger.debug("SecurityContext already authenticated before JwtAuthFilter for {} {}", requestMethod, requestPath);
                }
            } catch (JwtException error) {
                // token validation failed, so do not authenticate
                logger.debug(
                        "Bearer token could not be parsed or validated for {} {}: {}",
                        requestMethod,
                        requestPath,
                        error.getClass().getSimpleName());
            }
        }

        logger.debug("JwtAuthFilter finished {} {}", requestMethod, requestPath);

        filterChain.doFilter(request, response);
    }
}
