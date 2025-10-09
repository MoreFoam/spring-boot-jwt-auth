package org.foam.springbootjwtauth.model.database.auth;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@IdClass(Authority.AuthorityPK.class)
@Table(name = "authorities")
public class Authority implements GrantedAuthority {

    @Id
    @Column(nullable = false)
    private String username;

    @Id
    private String authority;

    @ManyToOne
    @JoinColumn(name = "username", referencedColumnName = "username", insertable = false, updatable = false)
    @JsonBackReference
    private User user;

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    public static class AuthorityPK implements Serializable {
        protected String username;
        protected String authority;
    }

}
