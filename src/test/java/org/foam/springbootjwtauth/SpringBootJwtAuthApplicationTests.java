package org.foam.springbootjwtauth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest(properties = {
        "spring-boot-jwt-auth.security.jwt.secret-key=dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdW5pdC10ZXN0cw=="
})
@Import(TestcontainersConfiguration.class)
class SpringBootJwtAuthApplicationTests {

    @Test
    void contextLoads() {
    }

}
