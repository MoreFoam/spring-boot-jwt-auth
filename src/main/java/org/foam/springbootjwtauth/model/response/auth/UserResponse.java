package org.foam.springbootjwtauth.model.response.auth;

import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {
    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String middleName;
    private String lastName;
    private String phoneNumber;
    private String profilePhotoUrl;
}
