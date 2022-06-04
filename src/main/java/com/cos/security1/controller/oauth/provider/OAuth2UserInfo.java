package com.cos.security1.controller.oauth.provider;

import com.cos.security1.model.User;

public interface OAuth2UserInfo {
    String getProviderId();
    String getProvider();
    String getEmail();
    String getUserName();
    default User makeNewUser(String password){
        return User.builder()
                .providerId(getProviderId())
                .provider(getProvider())
                .userName(getUserName())
                .password(password)
                .email(getEmail())
                .role("ROLE_USER")
                .build();
    }
}
