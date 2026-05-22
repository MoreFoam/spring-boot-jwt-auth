package org.foam.springbootjwtauth.model.response.auth;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class WebLoginResponse {
    private String accessToken;
    private String deviceId;
}
