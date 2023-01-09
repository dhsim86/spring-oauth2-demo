package com.dongho.oauth2demo.client.presentation.web;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.*;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
public class ArticlesController {

	private final WebClient webClient;

	@GetMapping(value = "/articles")
	public String[] getArticles(
		@RegisteredOAuth2AuthorizedClient("dongho-client-authorization-code") OAuth2AuthorizedClient authorizedClient
		//@RegisteredOAuth2AuthorizedClient("dongho-client-client-credential") OAuth2AuthorizedClient authorizedClient
	) {
		return this.webClient
			.get()
			.uri("http://127.0.0.1:8082/articles")
			.attributes(oauth2AuthorizedClient(authorizedClient))
			.retrieve()
			.bodyToMono(String[].class)
			.block();
	}
}
