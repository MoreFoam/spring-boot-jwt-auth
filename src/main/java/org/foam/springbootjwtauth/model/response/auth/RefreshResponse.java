package org.foam.springbootjwtauth.model.response.auth;

import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class RefreshResponse {
    private String accessToken;
}
