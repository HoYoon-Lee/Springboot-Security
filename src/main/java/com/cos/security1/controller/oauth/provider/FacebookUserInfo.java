package com.cos.security1.controller.oauth.provider;

import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor
public class FacebookUserInfo implements OAuth2UserInfo {
    private final Map<String, Object> attribute;

    @Override
    public String getProviderId() {
        return (String) attribute.get("id");
    }

    @Override
    public String getProvider() {
        return "facebook";
    }

    @Override
    public String getEmail() {
        return (String) attribute.get("email");
    }
}
