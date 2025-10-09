package org.foam.springbootjwtauth.service.auth;

import org.foam.springbootjwtauth.model.database.auth.Authority;
import org.foam.springbootjwtauth.repository.auth.AuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthorityService {

    private final AuthorityRepository authorityRepository;

    @Autowired
    public AuthorityService(AuthorityRepository authorityRepository) {
        this.authorityRepository = authorityRepository;
    }

    public List<Authority> getAuthoritiesByUsername(String username) {

        return authorityRepository.getAuthoritiesByUsername(username);
    }

    public Authority saveAuthority(Authority authority) {

        return authorityRepository.save(authority);
    }
}
