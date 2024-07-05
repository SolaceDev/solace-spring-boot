/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.solacesystems.jcsmp;

import org.springframework.lang.Nullable;

/**
 * Wrapper of JCSMP Singleton Factory to more easily work within Spring Auto Configuration
 * environments.
 */
public class SpringJCSMPFactory {

  protected JCSMPProperties jcsmpProperties;
  protected SolaceSessionOAuth2TokenProvider solaceSessionOAuth2TokenProvider;

  public SpringJCSMPFactory(JCSMPProperties properties,
      @Nullable SolaceSessionOAuth2TokenProvider solaceSessionOAuth2TokenProvider) {
    this.jcsmpProperties = (JCSMPProperties) properties.clone();
    this.solaceSessionOAuth2TokenProvider = solaceSessionOAuth2TokenProvider;
  }


  /**
   * Acquires a {@link JCSMPSession} implementation for the specified properties in the default
   * <code>Context</code>.
   *
   * @return A {@link JCSMPSession} implementation with the specified properties.
   * @throws InvalidPropertiesException Thrown if the required properties are not provided, or if
   *                                    unsupported properties (and combinations) are detected.
   */
  public JCSMPSession createSession() throws InvalidPropertiesException {
    return createSession(null);
  }

  /**
   * Acquires a {@link JCSMPSession} and associates it to the given {@link Context}.
   *
   * @param context The <code>Context</code> in which the new session will be created and associated
   *                with. If <code>null</code>, the default context is used.
   * @return A newly constructed session in <code>context</code>.
   * @throws InvalidPropertiesException on error
   */
  public JCSMPSession createSession(Context context) throws InvalidPropertiesException {
    return createSession(context, null);
  }

  /**
   * Acquires a {@link JCSMPSession} and associates it to the given {@link Context}.
   * If the authentication scheme is OAuth2, it fetches and sets the initial OAuth2 token.
   * If the event handler is null, it creates a new session event handler that will handle OAuth2 token refreshes.
   *
   * @param context      The <code>Context</code> in which the new session will be created and
   *                     associated with. If <code>null</code>, uses the default context.
   * @param eventHandler A callback instance for handling session events.
   * @return A newly constructed session in the <code>context</code> Context.
   * @throws InvalidPropertiesException on error
   */
  public JCSMPSession createSession(
      Context context,
      SessionEventHandler eventHandler) throws InvalidPropertiesException {
    if (JCSMPProperties.AUTHENTICATION_SCHEME_OAUTH2.equalsIgnoreCase(
        jcsmpProperties.getStringProperty(JCSMPProperties.AUTHENTICATION_SCHEME))) {

      //Fetch and set the initial OAuth2 token
      jcsmpProperties.setProperty(JCSMPProperties.OAUTH2_ACCESS_TOKEN,
          solaceSessionOAuth2TokenProvider.getAccessToken());

      if (eventHandler == null) {
        //Create a new session event handler that will handle OAuth2 token refreshes
        final DefaultSolaceOAuth2SessionEventHandler defaultSessionEventHandler = new DefaultSolaceOAuth2SessionEventHandler(
            this.jcsmpProperties, this.solaceSessionOAuth2TokenProvider);
        final JCSMPSession jcsmpSession = JCSMPFactory.onlyInstance()
            .createSession(jcsmpProperties, context, defaultSessionEventHandler);
        defaultSessionEventHandler.setJcsmpSession(jcsmpSession);
        return jcsmpSession;
      } else if (eventHandler instanceof SolaceOAuth2SessionEventHandler solaceOAuth2SessionEventHandler) {
        final JCSMPSession jcsmpSession = JCSMPFactory.onlyInstance()
            .createSession(jcsmpProperties, context, eventHandler);
        solaceOAuth2SessionEventHandler.setJcsmpSession(jcsmpSession);
        return jcsmpSession;
      } else {
        throw new IllegalArgumentException(
            "Event handler must be an instance of SolaceOAuth2SessionEventHandler");
      }
    }

    return JCSMPFactory.onlyInstance().createSession(jcsmpProperties, context, eventHandler);
  }

  /* CONTEXT OPERATIONS */
  /**
   * Returns a reference to the default <code>Context</code>. There is a single instance of a
   * default context in the API.
   *
   * @return The default <code>Context</code> instance.
   */
  public Context getDefaultContext() {
    return JCSMPFactory.onlyInstance().getDefaultContext();
  }

  /**
   * Creates a new <code>Context</code> with the provided properties.
   *
   * @param properties Configuration settings for the new <code>Context</code>. If
   *                   <code>null</code>, the default configuration settings are used.
   * @return Newly-created <code>Context</code> instance.
   */
  public Context createContext(ContextProperties properties) {
    return JCSMPFactory.onlyInstance().createContext(properties);
  }
}
