package com.deyvisonborges.eshop.authorizer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class InMemoryUserConfig {
    /**
   * Cria um serviço de detalhes do usuário em memória, configurando um usuário 
   * padrão com nome de usuário "user" e senha "password". Isso é útil para 
   * testes e demonstrações, mas em um ambiente de produção, você deve usar um 
   * serviço de detalhes do usuário persistente, como um banco de dados.
   * @return
   */
	@Bean 
	UserDetailsService userDetailsService() {
		UserDetails userDetails = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(userDetails);
	}
}
