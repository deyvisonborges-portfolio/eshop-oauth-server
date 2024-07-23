package com.deyvisonborges.eshop.auth_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean 
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(final HttpSecurity http) throws Exception {
    /**
     * Aplica a configuração padrão de segurança para o servidor de autorização OAuth2. 
     * Inclui a proteção dos endpoints de autorização e token, configurando as regras de acesso e 
     * autenticação necessárias para operar como um servidor OAuth2.
     */
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		
    /**
     * Habilita o suporte ao OpenID Connect (OIDC), permitindo que o servidor forneça funcionalidades 
     * adicionais de identidade, como login único (SSO).
     */
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0

    /**
     * Define o comportamento para redirecionar para a página de login (/login) quando 
     * um usuário não autenticado tenta acessar um endpoint protegido. 
     * O redirecionamento é configurado para requisições do tipo text/html.
     */
		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)

      /**
       * Configura o servidor para aceitar tokens JWT (JSON Web Tokens) 
       * como método de autenticação para acessar recursos protegidos.
       */
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer((resourceServer) -> resourceServer
				.jwt(Customizer.withDefaults()));

		return http.build();
	}

	@Bean 
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http) throws Exception {
    /**
     * Configura o filtro de segurança para autorizar todas as requisições apenas 
     * para usuários autenticados.
     */
		http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/test").permitAll());
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
      
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
      /**
       * Habilita a autenticação via formulário, permitindo que os usuários 
       * façam login através de uma página de login padrão.
       * 
       * Se eu habilitar essa opcao, eu posso customizar para onde 
       * o usuario eh levado para se autenticar
       * Vide ###001
       */
			.formLogin(Customizer.withDefaults()); // Habilita login via formulário
		return http.build();
	}
}