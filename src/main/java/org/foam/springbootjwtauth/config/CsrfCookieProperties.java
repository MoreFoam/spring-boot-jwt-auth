package org.foam.springbootjwtauth.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Component
@ConfigurationProperties(prefix = "spring-boot-jwt-auth.security.csrf-cookie")
public class CsrfCookieProperties {
    private String path = "/";
    private boolean secure = false;
    private String sameSite = "Lax";
}
