package com.solace.spring.boot.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

@Configuration
@ConditionalOnProperty(prefix = "solace.java.apiProperties", name = "AUTHENTICATION_SCHEME",
    havingValue = "AUTHENTICATION_SCHEME_OAUTH2")
public class OAuthClientConfiguration {

  @Bean
  public AuthorizedClientServiceOAuth2AuthorizedClientManager solaceOAuthAuthorizedClientServiceAndManager(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
    final OAuth2AuthorizedClientProvider clientCredentialsAuthorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .clientCredentials()
            .refreshToken()
            .build();

    final AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
        new AuthorizedClientServiceOAuth2AuthorizedClientManager(
            clientRegistrationRepository, oAuth2AuthorizedClientService);
    authorizedClientManager.setAuthorizedClientProvider(clientCredentialsAuthorizedClientProvider);

    return authorizedClientManager;
  }
}