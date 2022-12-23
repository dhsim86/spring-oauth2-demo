package com.dongho.oauth2demo.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfiguration {
/*
	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests(authorizeRequests ->
			authorizeRequests.anyRequest().authenticated()
		)
			.formLogin(Customizer.withDefaults());
		return http.build();
	}
*/
	@Bean
	public UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
			.username("dongho")
			.password("1234")
			.roles("USER")
			.build();
		return new InMemoryUserDetailsManager(user);
	}

}
