package org.foam.springbootjwtauth.model.response.auth;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class WebRefreshResponse {
    private String accessToken;
}
