package org.foam.springbootjwtauth.config;

import org.foam.springbootjwtauth.config.filter.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    private final CorsProperties corsProperties;

    private final CsrfCookieProperties csrfCookieProperties;

    @Autowired
    public SecurityConfig(
            JwtAuthFilter jwtAuthFilter,
            CorsProperties corsProperties,
            CsrfCookieProperties csrfCookieProperties) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.corsProperties = corsProperties;
        this.csrfCookieProperties = csrfCookieProperties;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        // set the name of the attribute the CsrfToken will be populated on
        requestHandler.setCsrfRequestAttributeName("_csrf");

        return http
                .authorizeHttpRequests(
                        requests -> requests
                                .requestMatchers("/auth/**").permitAll()
                                .requestMatchers(HttpMethod.POST, "/user/register").permitAll()
                                .requestMatchers("/user/**").authenticated()
                                .anyRequest().hasRole("ADMIN")
                )
                .securityContext(httpSecuritySecurityContextConfigurer ->
                        httpSecuritySecurityContextConfigurer
                                .securityContextRepository(securityContextRepository())
                )
                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer
                        .configurationSource(request -> {
                            CorsConfiguration configuration = new CorsConfiguration();
                            configuration.setAllowedOrigins(corsProperties.getAllowedOrigins());
                            configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
                            configuration.setAllowedHeaders(List.of("*"));
                            configuration.setAllowCredentials(true);
                            return configuration;
                        })
                )
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository())
                        .csrfTokenRequestHandler(requestHandler)
                        .ignoringRequestMatchers(request -> {
                            String contextPath = request.getContextPath();
                            String requestPath = request.getRequestURI().substring(contextPath.length());

                            return !requestPath.startsWith("/auth/web/");
                        })
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    private CookieCsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookiePath(csrfCookieProperties.getPath());
        repository.setCookieCustomizer(cookie -> cookie
                .secure(csrfCookieProperties.isSecure())
                .sameSite(csrfCookieProperties.getSameSite()));

        return repository;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new RequestAttributeSecurityContextRepository();
    }
}
