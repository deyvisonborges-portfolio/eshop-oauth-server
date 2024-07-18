package com.deyvisonborges.eshop.auth_server.config;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

@Configuration
public class ClientsStoreConfig {
  @Bean
  RegisteredClientRepository registeredClientRepository() {
    /**
     * Define um cliente registrado com um clientId, clientSecret, métodos de
     * autenticação,
     * tipos de concessão de autorização (Authorization Code e Refresh Token),
     * URIs de redirecionamento e escopos.
     * 
     * requireAuthorizationConsent(true): Indica que o consentimento do
     * usuário é necessário para a autorização.
     */
    RegisteredClient oidcClient = RegisteredClient
        .withId(UUID.randomUUID().toString())
        // informa quem 'e o client
        .clientId("client-server-id")
        .clientSecret("{noop}secret")

        /**
         * Define o método de autenticação que o cliente usará ao se comunicar
         * com o Authorization Server. O CLIENT_SECRET_BASIC é um método onde
         * o client_id e o client_secret são enviados como credenciais HTTP Basic.
         * 
         * Usado quando o cliente precisa se autenticar com o Authorization Server para
         * obter tokens.
         */
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

        /**
         * Define o tipo de concessão (grant type) que será usado pelo cliente.
         * O AUTHORIZATION_CODE é um tipo de concessão que envolve um redirecionamento
         * do usuário para o Authorization Server, onde ele autentica e autoriza a
         * aplicação.
         * 
         * Usado principalmente em aplicações web, onde o cliente é uma aplicação
         * frontend
         * que redireciona o usuário para um Authorization Server para autenticação.
         */
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)

        /**
         * Define a concessão para renovar tokens de acesso expirados
         * usando um token de atualização (refresh token).
         * 
         * Usado quando você precisa manter o usuário autenticado por
         * longos períodos sem solicitar reautenticação constante.
         */
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)

        /**
         * Especifica a URI de redirecionamento para onde o Authorization Server
         * enviará o código de autorização após a autenticação do usuário.
         * 
         * Necessário para o fluxo de concessão AUTHORIZATION_CODE. Deve ser uma URL
         * registrada no Authorization Server que a aplicação cliente pode manipular.
         */
        .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client-server-oidc")

        /**
         * Define a URI para onde o usuário será redirecionado após fazer logout.
         * 
         * Útil para redirecionar o usuário para uma página específica após o logout.
         */
        .postLogoutRedirectUri("http://127.0.0.1:8080/")

        /**
         * Define os escopos que o cliente está solicitando. OidcScopes.OPENID
         * é um escopo padrão para OpenID Connect, que permite obter informações
         * de identidade do usuário.
         * 
         * Usado em contextos onde a aplicação precisa obter informações sobre a
         * identidade do usuário, como durante o login com OpenID Connect.
         */
        .scope(OidcScopes.OPENID)

        /**
         * Outro escopo do OpenID Connect que permite acessar informações de perfil
         * do usuário, como nome e email.
         * 
         * Usado quando a aplicação precisa de informações detalhadas do perfil do
         * usuário.
         */
        .scope(OidcScopes.PROFILE)

        /**
         * Configurações adicionais do cliente. requireAuthorizationConsent(true) 
         * indica que o usuário deve dar consentimento explícito para as 
         * permissões solicitadas pela aplicação.
         * 
         * Útil para cenários onde você deseja garantir que o usuário 
         * esteja ciente e concorde com os acessos que a aplicação está solicitando.
         */
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        .build();

    /**
     * Armazena o cliente registrado em memória. Em um ambiente de produção,
     * você pode usar um repositório persistente, como um banco de dados.
     */
    return new InMemoryRegisteredClientRepository(oidcClient);
  }
}
