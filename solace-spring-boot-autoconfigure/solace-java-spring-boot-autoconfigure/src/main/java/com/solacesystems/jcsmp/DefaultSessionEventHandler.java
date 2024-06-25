package com.solacesystems.jcsmp;

import static com.solacesystems.jcsmp.SessionEvent.RECONNECTING;
import com.solace.spring.boot.autoconfigure.SolaceJavaProperties;
import java.util.Objects;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

public class DefaultSessionEventHandler implements SessionEventHandler {

  protected AuthorizedClientServiceOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
  protected JCSMPProperties jcsmpProperties;
  protected JCSMPSession jcsmpSession;

  public DefaultSessionEventHandler(JCSMPProperties jcsmpProperties,
      AuthorizedClientServiceOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager) {
    this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
    this.jcsmpProperties = jcsmpProperties;
  }

  @Override
  public void handleEvent(SessionEventArgs sessionEventArgs) {
    final SessionEvent event = sessionEventArgs.getEvent();

    if (RECONNECTING == event) {
      //accessToken.getExpiresAt().isBefore(Instant.now()) {
      if (JCSMPProperties.AUTHENTICATION_SCHEME_OAUTH2.equalsIgnoreCase(
          jcsmpProperties.getStringProperty(JCSMPProperties.AUTHENTICATION_SCHEME))) {

        final String clientUserName = Objects.toString(
            jcsmpProperties.getStringProperty(JCSMPProperties.USERNAME), "solace-java");
        final String oauth2ClientRegistrationId = jcsmpProperties.getStringProperty(
            SolaceJavaProperties.SPRING_OAUTH2_CLIENT_REGISTRATION_ID);
        final OAuth2AuthorizeRequest authorizeRequestInn =
            OAuth2AuthorizeRequest.withClientRegistrationId(oauth2ClientRegistrationId)
                .principal(clientUserName)
                .build();

        //Perform the actual authorization request using the authorized client service and authorized
        //client manager. This is where the JWT is retrieved from the OAuth/OIDC servers.
        final OAuth2AuthorizedClient oAuth2AuthorizedClientInn = Objects.requireNonNull(
            oAuth2AuthorizedClientManager).authorize(authorizeRequestInn);

        // Get the token from the authorized client object
        final OAuth2AccessToken accessToken = Objects.requireNonNull(oAuth2AuthorizedClientInn)
            .getAccessToken();
        try {
          jcsmpSession.setProperty(JCSMPProperties.OAUTH2_ACCESS_TOKEN,
              accessToken.getTokenValue());
        } catch (JCSMPException e) {
          e.printStackTrace();
        }
      }
    }
  }

  public void setJcsmpSession(JCSMPSession jcsmpSession) {
    this.jcsmpSession = jcsmpSession;
  }
}