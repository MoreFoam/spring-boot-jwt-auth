package org.foam.springbootjwtauth.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Component
@ConfigurationProperties(prefix = "spring-boot-jwt-auth.security.login")
public class LoginLockoutProperties {
    private int maxFailedAttempts = 5;
    private Duration lockDuration = Duration.ofMinutes(15);
}
