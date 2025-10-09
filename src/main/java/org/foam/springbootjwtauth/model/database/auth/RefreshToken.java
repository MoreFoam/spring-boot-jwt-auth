package org.foam.springbootjwtauth.model.database.auth;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "refresh_token")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(name = "token", unique = true)
    private String token;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "device_id")
    private String deviceId;
}
