package com.dongho.oauth2demo.resource.presentation.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class ArticlesController {

	@GetMapping("/articles")
	public String[] getArticles(@RequestHeader("Authorization") String authorizationHeader) {
		log.info("Authorization Header: {}", authorizationHeader);
		return new String[] {"Article 1", "Article 2", "Article 3"};
	}

}
