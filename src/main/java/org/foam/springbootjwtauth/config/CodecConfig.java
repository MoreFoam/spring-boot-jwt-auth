package org.foam.springbootjwtauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class CodecConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        int saltLength = 16;      // bytes
        int hashLength = 32;      // bytes
        int parallelism = 1;      // threads
        int memory = 65536;       // KB (64 MB)
        int iterations = 3;       // number of iterations

        return new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
    }
}
