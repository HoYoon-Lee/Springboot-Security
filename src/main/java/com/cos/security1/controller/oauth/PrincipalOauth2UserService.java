package com.cos.security1.controller.oauth;

import com.cos.security1.controller.auth.PrincipalDetails;
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
        String providerId = oAuth2User.getAttribute("sub");
        String userName = String.join("_", provider, providerId);
        String password = encoder.encode("GetInThere");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User user = userRepository.findByUserName(userName);

        if(user == null){
          user = User.builder()
                  .userName(userName)
                  .password(password)
                  .email(email)
                  .role(role)
                  .provider(provider)
                  .providerId(providerId)
                  .build();
          userRepository.save(user);
        }

        System.out.println("userRequest: " + userRequest.getClientRegistration());
        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
