/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package cz.muni.ics.oauth2.service.impl;

import com.google.common.collect.ImmutableMap;
import cz.muni.ics.oauth2.model.OAuth2AccessTokenEntity;
import cz.muni.ics.oauth2.model.OAuth2RefreshTokenEntity;
import cz.muni.ics.oauth2.service.IntrospectionResultAssembler;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import static com.google.common.collect.Sets.newHashSet;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

public class TestDefaultIntrospectionResultAssembler {

	private final IntrospectionResultAssembler assembler = new DefaultIntrospectionResultAssembler();

	@Test
	public void shouldAssembleExpectedResultForAccessToken() {
		// given
		OAuth2AccessTokenEntity accessToken = accessToken(new Date(123 * 1000L), scopes("foo", "bar"), "Bearer",
				oauth2AuthenticationWithUser(oauth2Request("clientId"), "name"));

		Set<String> authScopes = scopes("foo", "bar", "baz");

		// when
		Map<String, Object> result = assembler.assembleFrom(accessToken, authScopes);

		// then
		Map<String, Object> expected = new ImmutableMap.Builder<String, Object>()
				.put("exp", 123L)
				.put("scope", "bar foo")
				.put("active", Boolean.TRUE)
				.put("username", "name")
				.put("client_id", "clientId")
				.put("token_type", "Bearer")
				.put("auth_time", 0L)
				.build();
		assertThat(result, is(equalTo(expected)));
	}

	@Test
	public void shouldAssembleExpectedResultForAccessTokenWithoutUserInfo() {

		// given
		OAuth2AccessTokenEntity accessToken = accessToken(new Date(123 * 1000L), scopes("foo", "bar"), "Bearer",
				oauth2AuthenticationWithUser(oauth2Request("clientId"), "name"));

		Set<String> authScopes = scopes("foo", "bar", "baz");

		// when
		Map<String, Object> result = assembler.assembleFrom(accessToken, authScopes);


		// then
		Map<String, Object> expected = new ImmutableMap.Builder<String, Object>()
				.put("exp", 123L)
				.put("scope", "bar foo")
				.put("active", Boolean.TRUE)
				.put("username", "name")
				.put("client_id", "clientId")
				.put("token_type", "Bearer")
				.put("auth_time", 0L)
				.build();
		assertThat(result, is(equalTo(expected)));
	}

	@Test
	public void shouldAssembleExpectedResultForAccessTokenWithoutExpiry() {
		// given
		OAuth2AccessTokenEntity accessToken = accessToken(null, scopes("foo", "bar"), "Bearer",
				oauth2AuthenticationWithUser(oauth2Request("clientId"), "name"));

		Set<String> authScopes = scopes("foo", "bar", "baz");

		// when
		Map<String, Object> result = assembler.assembleFrom(accessToken, authScopes);


		// then
		Map<String, Object> expected = new ImmutableMap.Builder<String, Object>()
				.put("scope", "bar foo")
				.put("active", Boolean.TRUE)
				.put("username", "name")
				.put("client_id", "clientId")
				.put("token_type", "Bearer")
				.put("auth_time", 0L)
				.build();
		assertThat(result, is(equalTo(expected)));
	}

	@Test
	public void shouldAssembleExpectedResultForAccessTokenWithoutUserAuthentication() {
		// given
		OAuth2AccessTokenEntity accessToken = accessToken(new Date(123 * 1000L), scopes("foo", "bar"), "Bearer",
				oauth2Authentication(oauth2Request("clientId"), null));

		Set<String> authScopes = scopes("foo", "bar", "baz");

		// when
		Map<String, Object> result = assembler.assembleFrom(accessToken, authScopes);


		// then `user_id` should not be present
		Map<String, Object> expected = new ImmutableMap.Builder<String, Object>()
				.put("exp", 123L)
				.put("scope", "bar foo")
				.put("active", Boolean.TRUE)
				.put("client_id", "clientId")
				.put("token_type", "Bearer")
				.put("auth_time", 0L)
				.build();
		assertThat(result, is(equalTo(expected)));
	}

	@Test
	public void shouldAssembleExpectedResultForRefreshToken() {

		// given
		OAuth2RefreshTokenEntity refreshToken = refreshToken(new Date(123 * 1000L),
				oauth2AuthenticationWithUser(oauth2Request("clientId", scopes("foo", "bar")), "name"));

		Set<String> authScopes = scopes("foo", "bar", "baz");

		// when
		Map<String, Object> result = assembler.assembleFrom(refreshToken, authScopes);


		// then
		Map<String, Object> expected = new ImmutableMap.Builder<String, Object>()
				.put("scope", "bar foo")
				.put("client_id", "clientId")
				.put("token_type", "refresh_token")
				.put("exp", 123L)
				.put("username", "name")
				.put("auth_time", 0L)
				.put("active", Boolean.TRUE)
				.build();
		assertThat(result, is(equalTo(expected)));
	}

	@Test
	public void shouldAssembleExpectedResultForRefreshTokenWithoutUserInfo() {

		// given
		OAuth2RefreshTokenEntity refreshToken = refreshToken(new Date(123 * 1000L),
				oauth2AuthenticationWithUser(oauth2Request("clientId", scopes("foo",  "bar")), "name"));

		Set<String> authScopes = scopes("foo", "bar", "baz");

		// when
		Map<String, Object> result = assembler.assembleFrom(refreshToken, authScopes);


		// then
		Map<String, Object> expected = new ImmutableMap.Builder<String, Object>()
				.put("exp", 123L)
				.put("scope", "bar foo")
				.put("active", Boolean.TRUE)
				.put("username", "name")
				.put("client_id", "clientId")
				.put("token_type", "refresh_token")
				.put("auth_time", 0L)
				.build();
		assertThat(result, is(equalTo(expected)));
	}

	@Test
	public void shouldAssembleExpectedResultForRefreshTokenWithoutExpiry() {

		// given
		OAuth2RefreshTokenEntity refreshToken = refreshToken(null,
				oauth2AuthenticationWithUser(oauth2Request("clientId", scopes("foo",  "bar")), "name"));

		Set<String> authScopes = scopes("foo", "bar", "baz");

		// when
		Map<String, Object> result = assembler.assembleFrom(refreshToken, authScopes);


		// then
		Map<String, Object> expected = new ImmutableMap.Builder<String, Object>()
				.put("scope", "bar foo")
				.put("active", Boolean.TRUE)
				.put("username", "name")
				.put("client_id", "clientId")
				.put("token_type", "refresh_token")
				.put("auth_time", 0L)
				.build();
		assertThat(result, is(equalTo(expected)));
	}

	@Test
	public void shouldAssembleExpectedResultForRefreshTokenWithoutUserAuthentication() throws ParseException {
		// given
		OAuth2RefreshTokenEntity refreshToken = refreshToken(null,
				oauth2Authentication(oauth2Request("clientId", scopes("foo",  "bar")), null));

		Set<String> authScopes = scopes("foo", "bar", "baz");

		// when
		Map<String, Object> result = assembler.assembleFrom(refreshToken, authScopes);


		// then `user_id` should not be present
		Map<String, Object> expected = new ImmutableMap.Builder<String, Object>()
				.put("scope", "bar foo")
				.put("active", Boolean.TRUE)
				.put("client_id", "clientId")
				.put("token_type", "refresh_token")
				.put("auth_time", 0L)
				.build();
		assertThat(result, is(equalTo(expected)));
	}

	private OAuth2AccessTokenEntity accessToken(Date exp, Set<String> scopes, String tokenType, OAuth2Authentication authentication) {
		OAuth2AccessTokenEntity accessToken = mock(OAuth2AccessTokenEntity.class, RETURNS_DEEP_STUBS);
		given(accessToken.getExpiration()).willReturn(exp);
		given(accessToken.getScope()).willReturn(scopes);
		given(accessToken.getTokenType()).willReturn(tokenType);
		given(accessToken.getAuthenticationHolder().getAuthentication()).willReturn(authentication);
		return accessToken;
	}

	private OAuth2RefreshTokenEntity refreshToken(Date exp, OAuth2Authentication authentication) {
		OAuth2RefreshTokenEntity refreshToken = mock(OAuth2RefreshTokenEntity.class, RETURNS_DEEP_STUBS);
		given(refreshToken.getExpiration()).willReturn(exp);
		given(refreshToken.getAuthenticationHolder().getAuthentication()).willReturn(authentication);
		return refreshToken;
	}

	private OAuth2Authentication oauth2AuthenticationWithUser(OAuth2Request request, String username) {
		UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(username, "somepassword");
		return oauth2Authentication(request, userAuthentication);
	}

	private OAuth2Authentication oauth2Authentication(OAuth2Request request, Authentication userAuthentication) {
		return new OAuth2Authentication(request, userAuthentication);
	}

	private OAuth2Request oauth2Request(String clientId) {
		return oauth2Request(clientId, null);
	}

	private OAuth2Request oauth2Request(String clientId, Set<String> scopes) {
		return new OAuth2Request(null, clientId, null, true, scopes, null, null, null, null);
	}

	private Set<String> scopes(String... scopes) {
		return newHashSet(scopes);
	}
}
