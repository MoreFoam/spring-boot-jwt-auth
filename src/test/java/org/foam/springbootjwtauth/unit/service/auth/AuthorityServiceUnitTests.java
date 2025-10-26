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

        List<Authority> authorities = new ArrayList<>();
        Authority authority = new Authority();
        authority.setAuthority("ROLE_USER");
        authority.setUsername(username);
        authorities.add(authority);

        when(authorityRepository.getAuthoritiesByUsername(username)).thenReturn(authorities);

        // Act
        List<Authority> returnedAuthorities = authorityService.getAuthoritiesByUsername(username);

        // Assert
        assertEquals(returnedAuthorities.size(), 1);
        assertEquals(returnedAuthorities.get(0).getAuthority(), authority.getAuthority());
        assertEquals(returnedAuthorities.get(0).getUsername(), authority.getUsername());

        // Verify
        verify(authorityRepository).getAuthoritiesByUsername(username);
    }

    @Test
    void testSaveAuthority() {
        // Arrange
        Authority authority = new Authority();
        authority.setAuthority("ROLE_USER");
        authority.setUsername("user");

        when(authorityRepository.save(authority)).thenReturn(authority);

        // Act
        Authority returnedAuthority = authorityService.saveAuthority(authority);

        // Assert
        assertEquals(returnedAuthority.getAuthority(), authority.getAuthority());
        assertEquals(returnedAuthority.getUsername(), authority.getUsername());

        // Verify
        verify(authorityRepository).save(authority);
    }
}
