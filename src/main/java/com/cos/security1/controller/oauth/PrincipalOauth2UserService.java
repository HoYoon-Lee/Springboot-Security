package com.cos.security1.controller.oauth;

import com.cos.security1.controller.auth.PrincipalDetails;
import com.cos.security1.controller.oauth.provider.FacebookUserInfo;
import com.cos.security1.controller.oauth.provider.GoogleUserInfo;
import com.cos.security1.controller.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo;
        switch (provider){
            case "google":
                System.out.println("google 로그인 요청");
                oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
                break;
            case "facebook":
                System.out.println("facebook 로그인 요청");
                oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
                break;
            default:
                try {
                    throw new Exception("지원하지 않는 로그인 방식입니다.");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
        }

        User user = userRepository.findByUserName(oAuth2UserInfo.getUserName());

        if(user == null){
            user = oAuth2UserInfo.makeNewUser(encoder.encode("GetInThere"));
            userRepository.save(user);
        }

        System.out.println("userRequest: " + userRequest.getClientRegistration());
        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
