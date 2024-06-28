package com.solacesystems.jcsmp;

import java.util.Objects;

/**
 * Default implementation of SolaceOAuth2SessionEventHandler. This class handles the OAuth2 token
 * refresh logic when the session is reconnecting.
 */
public class DefaultSolaceOAuth2SessionEventHandler implements SolaceOAuth2SessionEventHandler {

  protected final SolaceSessionOAuth2TokenProvider solaceSessionOAuth2TokenProvider;
  protected final JCSMPProperties jcsmpProperties;
  protected JCSMPSession jcsmpSession;

  /**
   * Constructs a new DefaultSolaceOAuth2SessionEventHandler with the provided JCSMP properties and
   * OAuth2 token provider.
   *
   * @param jcsmpProperties                  The JCSMP properties.
   * @param solaceSessionOAuth2TokenProvider The OAuth2 token provider.
   */
  public DefaultSolaceOAuth2SessionEventHandler(JCSMPProperties jcsmpProperties,
      SolaceSessionOAuth2TokenProvider solaceSessionOAuth2TokenProvider) {
    Objects.requireNonNull(jcsmpProperties);
    Objects.requireNonNull(solaceSessionOAuth2TokenProvider);
    this.solaceSessionOAuth2TokenProvider = solaceSessionOAuth2TokenProvider;
    this.jcsmpProperties = jcsmpProperties;
  }

  @Override
  public void handleEvent(SessionEventArgs sessionEventArgs) {
    final SessionEvent event = sessionEventArgs.getEvent();

    if (event == SessionEvent.RECONNECTING) {
      handleReconnectingEvent();
    }
  }

  private void handleReconnectingEvent() {
    if (JCSMPProperties.AUTHENTICATION_SCHEME_OAUTH2.equalsIgnoreCase(
        jcsmpProperties.getStringProperty(JCSMPProperties.AUTHENTICATION_SCHEME))) {
      try {
        final String newAccessToken = solaceSessionOAuth2TokenProvider.getAccessToken();
        jcsmpSession.setProperty(JCSMPProperties.OAUTH2_ACCESS_TOKEN, newAccessToken);
      } catch (JCSMPException e) {
        e.printStackTrace(); //TODO: log this properly
      }
    }
  }

  @Override
  public void setJcsmpSession(JCSMPSession jcsmpSession) {
    this.jcsmpSession = jcsmpSession;
  }
}