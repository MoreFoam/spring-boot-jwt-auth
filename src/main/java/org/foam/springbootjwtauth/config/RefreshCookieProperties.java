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
@ConfigurationProperties(prefix = "spring-boot-jwt-auth.security.refresh-cookie")
public class RefreshCookieProperties {
    private String name = "refreshToken";
    private String path = "/api/auth/web";
    private boolean secure = false;
    private String sameSite = "Lax";
    private long maxAgeSeconds = 5_184_000;
}
