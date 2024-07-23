package com.deyvisonborges.eshop.authorizer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

@Configuration
public class AuthorizationServerConfig {
  @Bean 
	AuthorizationServerSettings authorizationServerSettings() {
    /**
     * Configura as definições do servidor de autorização. 
     * Pode incluir detalhes como os endpoints de autorização e token. 
     * No exemplo, é utilizado o builder padrão, que aplica configurações padrão.
     */
		return AuthorizationServerSettings.builder().build();
	}
}
