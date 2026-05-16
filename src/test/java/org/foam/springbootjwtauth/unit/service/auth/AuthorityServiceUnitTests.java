package org.foam.springbootjwtauth.unit.service.auth;

import org.foam.springbootjwtauth.model.database.auth.Authority;
import org.foam.springbootjwtauth.repository.auth.AuthorityRepository;
import org.foam.springbootjwtauth.service.auth.AuthorityService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthorityServiceUnitTests {

    @Mock
    AuthorityRepository authorityRepository;

    @InjectMocks
    private AuthorityService authorityService;

    @Test
    void testGetAuthoritiesByUsername() {
        // Arrange
        String username = "user";
        org.foam.springbootjwtauth.model.database.auth.User user = new org.foam.springbootjwtauth.model.database.auth.User();
        user.setUsername(username);

        List<Authority> authorities = new ArrayList<>();
        Authority authority = new Authority();
        authority.setAuthority("ROLE_USER");
        authority.setUser(user);
        authorities.add(authority);

        when(authorityRepository.getAuthoritiesByUserUsername(username)).thenReturn(authorities);

        // Act
        List<Authority> returnedAuthorities = authorityService.getAuthoritiesByUsername(username);

        // Assert
        assertEquals(1, returnedAuthorities.size());
        assertEquals(authority.getAuthority(), returnedAuthorities.get(0).getAuthority());
        assertEquals(username, returnedAuthorities.get(0).getUser().getUsername());

        // Verify
        verify(authorityRepository).getAuthoritiesByUserUsername(username);
    }

    @Test
    void testSaveAuthority() {
        // Arrange
        Authority authority = new Authority();
        authority.setAuthority("ROLE_USER");

        when(authorityRepository.save(authority)).thenReturn(authority);

        // Act
        Authority returnedAuthority = authorityService.saveAuthority(authority);

        // Assert
        assertEquals(authority.getAuthority(), returnedAuthority.getAuthority());

        // Verify
        verify(authorityRepository).save(authority);
    }
}
