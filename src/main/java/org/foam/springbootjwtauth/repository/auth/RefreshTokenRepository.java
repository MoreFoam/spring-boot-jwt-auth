package org.foam.springbootjwtauth.repository.auth;

import lombok.NonNull;
import org.foam.springbootjwtauth.model.database.auth.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(@NonNull String token);
}
