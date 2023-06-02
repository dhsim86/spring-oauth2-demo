package com.dongho.oauth2demo.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// TODO: authorization code grants
		/*http
			.authorizeRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.oauth2Login(oauth2Login ->
				oauth2Login.loginPage("/oauth2/authorization/client-oidc"))
			.oauth2Client(Customizer.withDefaults());*/

		// TODO: client credentials
		http
			.authorizeRequests().anyRequest().permitAll()
				.and()
			.oauth2Client(Customizer.withDefaults());
		return http.build();
	}

}
