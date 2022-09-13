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

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import cz.muni.ics.oauth2.model.AuthenticationHolderEntity;
import cz.muni.ics.oauth2.model.AuthenticationStatement;
import cz.muni.ics.oauth2.model.OAuth2AccessTokenEntity;
import cz.muni.ics.oauth2.model.OAuth2RefreshTokenEntity;
import cz.muni.ics.oauth2.model.SamlAuthenticationDetails;
import cz.muni.ics.oauth2.model.SavedUserAuthentication;
import cz.muni.ics.oauth2.service.IntrospectionResultAssembler;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.text.ParseException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.google.common.collect.Maps.newLinkedHashMap;

/**
 * Default implementation of the {@link IntrospectionResultAssembler} interface.
 */
@Service
@Slf4j
public class DefaultIntrospectionResultAssembler implements IntrospectionResultAssembler {

	@Override
	public Map<String, Object> assembleFrom(OAuth2AccessTokenEntity token, Set<String> introspectionRequesterScopes) {
		AuthenticationHolderEntity authenticationHolder = token.getAuthenticationHolder();
		OAuth2Authentication authentication = (authenticationHolder != null) ?
				authenticationHolder.getAuthentication() : null;

		Set<String> scopes = Sets.intersection(introspectionRequesterScopes, token.getScope());
		String scope = Joiner.on(SCOPE_SEPARATOR).join(scopes);
		Long exp = null;
		if (token.getExpiration() != null) {
			exp = token.getExpiration().getTime() / 1000L;
		} else {
			log.warn("WARNING - ACCESS TOKEN WITHOUT EXPIRATION DATE DETECTED ('{}')", token);
		}

		String clientId = (authentication != null && authentication.getOAuth2Request() != null) ?
				authentication.getOAuth2Request().getClientId() : null;
		if (clientId == null) {
			clientId = (token.getClient() != null) ? token.getClient().getClientId() : null;
		}

		String tokenType = OAuth2AccessToken.BEARER_TYPE;
		JWT jwtValue = token.getJwtValue();
		String username = (authenticationHolder != null
						   && authenticationHolder.getAuthentication() != null
						   && authenticationHolder.getAuthentication().getUserAuthentication() != null) ?
				authenticationHolder.getAuthentication().getUserAuthentication().getName() : null;

		Map<String, Object> result = assemble(scope, exp, username, clientId, tokenType, jwtValue, authenticationHolder);

		if (!token.isExpired()) {
			result.put(ACTIVE, true);
		} else {
			result.clear();
			result.put(ACTIVE, false);
		}
		return result;
	}

	@Override
	public Map<String, Object> assembleFrom(OAuth2RefreshTokenEntity token, Set<String> introspectionRequesterScopes) {
		AuthenticationHolderEntity authenticationHolder = token.getAuthenticationHolder();
		OAuth2Authentication authentication = (authenticationHolder != null) ?
				authenticationHolder.getAuthentication() : null;
		Set<String> tokenScopes = (authentication != null && authentication.getOAuth2Request() != null) ?
				authentication.getOAuth2Request().getScope() : new HashSet<>();

		Set<String> scopes = Sets.intersection(introspectionRequesterScopes, tokenScopes);
		String scope = Joiner.on(SCOPE_SEPARATOR).join(scopes);
		Long exp = null;
		if (token.getExpiration() != null) {
			exp = token.getExpiration().getTime() / 1000L;
		} else {
			log.warn("WARNING - REFRESH TOKEN WITHOUT EXPIRATION DATE DETECTED ('{}')", token);
		}

		String clientId = (authentication != null && authentication.getOAuth2Request() != null) ?
				authentication.getOAuth2Request().getClientId() : null;
		String username = (authentication != null && authentication.getUserAuthentication() != null) ?
			authentication.getUserAuthentication().getName() : null;
		String tokenType = "refresh_token";
		JWT jwtValue = token.getJwt();

		Map<String, Object> result = assemble(scope, exp, username, clientId, tokenType, jwtValue, authenticationHolder);

		if (!token.isExpired()) {
			result.put(ACTIVE, true);
		} else {
			result.clear();
			result.put(ACTIVE, false);
		}
		return result;
	}

	private Map<String, Object> assemble(String scope,
										 Long exp,
										 String username,
										 String clientId,
										 String tokenType,
										 JWT jwtValue,
										 AuthenticationHolderEntity authenticationHolder)
	{
		Map<String, Object> result = new LinkedHashMap<>();
		if (scope != null && !scope.isEmpty()) {
			result.put(SCOPE, scope);
		}
		if (StringUtils.hasText(clientId)) {
			result.put(CLIENT_ID, clientId);
		}
		if (StringUtils.hasText(tokenType)) {
			result.put(TOKEN_TYPE, tokenType);
		}
		if (exp != null) {
			result.put(EXP, exp);
		}
		if (StringUtils.hasText(username)) {
			result.put(USERNAME, username);
		}
		if (jwtValue != null) {
			fillDataFromJwt(jwtValue, result);
		}
		if (authenticationHolder != null && authenticationHolder.getUserAuth() != null) {
			fillAcrAndAuthTime(authenticationHolder.getUserAuth(), result);
		}
		return result;
	}

	private void fillDataFromJwt(JWT atJwt, Map<String, Object> result) {
		try {
			JWTClaimsSet atClaimsSet = atJwt.getJWTClaimsSet();
			if (atClaimsSet != null) {
				if (atClaimsSet.getIssueTime() != null) {
					result.put(IAT, atClaimsSet.getIssueTime().getTime() / 1000L);
				}
				if (atClaimsSet.getNotBeforeTime() != null) {
					result.put(NBF, atClaimsSet.getNotBeforeTime().getTime() / 1000L);
				}
				if (StringUtils.hasText(atClaimsSet.getSubject())) {
					result.put(SUB, atClaimsSet.getSubject());
				}
				if (atClaimsSet.getAudience() != null) {
					result.put(AUD, atClaimsSet.getAudience());
				}
				if (StringUtils.hasText(atClaimsSet.getIssuer())) {
					result.put(ISS, atClaimsSet.getIssuer());
				}
				if (StringUtils.hasText(atClaimsSet.getJWTID())) {
					result.put(JTI, atClaimsSet.getJWTID());
				}
			}
		} catch (ParseException e) {
			log.warn("Caught exception while introspecting token and parsing JWT value '{}'", atJwt, e);
		}
	}

	private void fillAcrAndAuthTime(SavedUserAuthentication savedUserAuthentication, Map<String, Object> result) {
		if (StringUtils.hasText(savedUserAuthentication.getAcr())) {
			result.put(ACR, savedUserAuthentication.getAcr());
		}
		if (savedUserAuthentication.getAuthTime() != null) {
			result.put(AUTH_TIME, savedUserAuthentication.getAuthTime());
		}
	}

}
