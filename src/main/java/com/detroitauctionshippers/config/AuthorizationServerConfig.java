/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.detroitauctionshippers.config;

import java.lang.reflect.Member;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import com.detroitauctionshippers.domain.AppUser;
import com.detroitauctionshippers.domain.Authority;
import com.detroitauctionshippers.jose.Jwks;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * @author Nikhil
 * @since 0.0.1
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {


	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		
		 http.cors(c -> {
		      CorsConfigurationSource source = s -> {
		        CorsConfiguration cc = new CorsConfiguration();
		        cc.setAllowCredentials(true);
		        cc.setAllowedOrigins(List.of("http://127.0.0.1:3000"));
		        cc.setAllowedHeaders(List.of("*"));
		        cc.setAllowedMethods(List.of("*"));
		        return cc;
		      };

		      c.configurationSource(source);
		    });

	
		http
			.exceptionHandling(exceptions ->
				exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			)
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
	
		return http.build();
	}


	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		
//		  RegisteredClient registeredClient =
//		  RegisteredClient.withId(UUID.randomUUID().toString()) 
//		  .clientId("messaging-client") 
//		  .clientSecret(SecurityUtility.passwordEncoder().encode("secret")) 
//		  .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//		  .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) 
//		  .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) 
//		  .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) 
//		  .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
//		  .redirectUri("http://127.0.0.1:8080/authorized") 
//		  .scope(OidcScopes.OPENID) 
//		  .scope(OidcScopes.PROFILE) 
//		  .scope("message.read") 
//		  .scope("message.write") 
//		  .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).
//		  build())
//		  .build();
		 
		// Save registered client in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		//registeredClientRepository.save(registeredClient);

		return registeredClientRepository;
	}
	// @formatter:on

//	@Bean
//	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
//		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
//	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
	 @Bean
	   public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
	      JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	      jdbcOAuth2AuthorizationService.setAuthorizationRowMapper(new RowMapper(registeredClientRepository));
	      return jdbcOAuth2AuthorizationService;
	   }
	   
	   static class RowMapper extends JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper {
	      RowMapper(RegisteredClientRepository registeredClientRepository) {
	         super(registeredClientRepository);
	         getObjectMapper().addMixIn(AppUser.class, AppUserMixin.class);
	         getObjectMapper().addMixIn(Authority.class, AuthorityMixin.class);

	      }
	   }
	   
	    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
	    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
	          isGetterVisibility = JsonAutoDetect.Visibility.NONE)
	    @JsonIgnoreProperties(ignoreUnknown = true)
	    static class AppUserMixin {

	       @JsonCreator
	       public AppUserMixin(@JsonProperty("id") Long id, @JsonProperty("username") String user, @JsonProperty("password") String password) {
	       }
	       
	       

	    }
	    
	    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
	    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
	          isGetterVisibility = JsonAutoDetect.Visibility.NONE)
	    @JsonIgnoreProperties(ignoreUnknown = true)
	    static class AuthorityMixin {

	       @JsonCreator
	       public AuthorityMixin(@JsonProperty("authority") String authority) {
	       }
	       
	       

	    }
}
