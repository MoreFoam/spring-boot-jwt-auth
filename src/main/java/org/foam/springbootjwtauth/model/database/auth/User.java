package org.foam.springbootjwtauth.model.database.auth;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
@Setter
@ToString()
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(length = 100, nullable = false)
    @ToString.Exclude
    private String password;

    @Column(nullable = false)
    private Boolean enabled;

    @Column(unique = true, nullable = false)
    private String email;

    @ToString.Exclude
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.EAGER, orphanRemoval = true)
    @JsonManagedReference
    private List<Authority> authorities;

    @Column(nullable = false)
    private boolean accountNonExpired;

    @Column(nullable = false)
    private boolean accountNonLocked;

    @Column(nullable = false)
    private boolean credentialsNonExpired;

    @Override
    public Collection<Authority> getAuthorities() {
        return authorities;
    }

    public List<String> getRoleNames() {
        return getAuthorities().stream()
                .map(Authority::getAuthority)
                .toList();
    }


    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    public boolean isAdmin() {
        return authorities.stream().anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
    }
}
