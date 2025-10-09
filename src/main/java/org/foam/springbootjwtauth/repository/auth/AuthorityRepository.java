package org.foam.springbootjwtauth.repository.auth;

import lombok.NonNull;
import org.foam.springbootjwtauth.model.database.auth.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthorityRepository extends JpaRepository<Authority, Authority.AuthorityPK> {

    List<Authority> getAuthoritiesByUsername(@NonNull String username);
}
