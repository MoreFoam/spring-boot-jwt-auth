package org.foam.springbootjwtauth.repository.auth;

import lombok.NonNull;
import org.foam.springbootjwtauth.model.database.auth.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {

    List<Authority> getAuthoritiesByUserUsername(@NonNull String username);
}
