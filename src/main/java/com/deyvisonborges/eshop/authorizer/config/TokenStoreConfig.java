package com.deyvisonborges.eshop.authorizer.config;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class TokenStoreConfig {

  private static final Logger logger = LoggerFactory.getLogger(TokenStoreConfig.class);

  @Value("${rsa.public}")
  private String publicRsaKey;

  @Value("${rsa.private}")
  private String privateRsaKey;

  @Bean
  JWKSource<SecurityContext> jwkSource() throws Exception {
    RSAPublicKey publicKey = getPublicKey(publicRsaKey);
    RSAPrivateKey privateKey = getPrivateKey(privateRsaKey);

    RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private RSAPublicKey getPublicKey(String key) throws Exception {
    String cleanedKey = key
            .replaceAll("-----BEGIN PUBLIC KEY-----", "")
            .replaceAll("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");
    logger.info("Cleaned Public Key: {}", cleanedKey); // Adicione logging para depuração
    byte[] decoded = Base64.getDecoder().decode(cleanedKey);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) keyFactory.generatePublic(spec);
  }

  private RSAPrivateKey getPrivateKey(String key) throws Exception {
    String cleanedKey = key
            .replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
            .replaceAll("-----END RSA PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");
    logger.info("Cleaned Private Key: {}", cleanedKey); // Adicione logging para depuração
    byte[] decoded = Base64.getDecoder().decode(cleanedKey);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPrivateKey) keyFactory.generatePrivate(spec);
  }

  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }
}
