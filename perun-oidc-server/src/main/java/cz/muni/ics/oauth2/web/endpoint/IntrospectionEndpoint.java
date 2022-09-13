/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
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
package cz.muni.ics.oauth2.web.endpoint;

import com.google.common.collect.ImmutableMap;
import cz.muni.ics.oauth2.model.ClientDetailsEntity;
import cz.muni.ics.oauth2.model.OAuth2AccessTokenEntity;
import cz.muni.ics.oauth2.model.OAuth2RefreshTokenEntity;
import cz.muni.ics.oauth2.service.ClientDetailsEntityService;
import cz.muni.ics.oauth2.service.IntrospectionResultAssembler;
import cz.muni.ics.oauth2.service.OAuth2TokenEntityService;
import cz.muni.ics.oauth2.web.AuthenticationUtilities;
import cz.muni.ics.openid.connect.model.UserInfo;
import cz.muni.ics.openid.connect.service.UserInfoService;
import cz.muni.ics.openid.connect.view.HttpCodeView;
import cz.muni.ics.openid.connect.view.JsonEntityView;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Slf4j
public class IntrospectionEndpoint {

	public static final String URL = "introspect";

	public static final String PARAM_TOKEN = "token";
	public static final String PARAM_TOKEN_TYPE_HINT = "token_type_hint";

	private final OAuth2TokenEntityService tokenServices;
	private final ClientDetailsEntityService clientService;
	private final IntrospectionResultAssembler introspectionResultAssembler;
	private final UserInfoService userInfoService;

	@Autowired
	public IntrospectionEndpoint(OAuth2TokenEntityService tokenServices,
								 ClientDetailsEntityService clientService,
								 IntrospectionResultAssembler introspectionResultAssembler,
								 UserInfoService userInfoService)
	{
		this.tokenServices = tokenServices;
		this.clientService = clientService;
		this.introspectionResultAssembler = introspectionResultAssembler;
		this.userInfoService = userInfoService;
	}

	@RequestMapping("/" + URL)
	public String introspect(@RequestParam(PARAM_TOKEN) String token,
							 @RequestParam(value = PARAM_TOKEN_TYPE_HINT, required = false) String tokenTypeHint,
							 Authentication auth,
							 Model model)
	{
		if (auth == null) {
			log.error("No authentication object available in the introspection endpoint");
			return codeErrorResponse(model, HttpStatus.UNAUTHORIZED);
		}

		String authClientId = auth.getName();
		if (!StringUtils.hasText(authClientId)) {
			log.error("No client_id object available in the introspection endpoint");
			return codeErrorResponse(model, HttpStatus.INTERNAL_SERVER_ERROR);
		}

		ClientDetailsEntity authClient = clientService.loadClientByClientId(authClientId);
		if (authClient == null) {
			log.error("No client found for client_id '{}'", authClientId);
			return codeErrorResponse(model, HttpStatus.BAD_REQUEST);
		} else if (!AuthenticationUtilities.hasRole(auth, "ROLE_CLIENT") || !authClient.isAllowIntrospection()) {
			log.error("Client '{}' is not allowed to call introspection endpoint", authClient.getClientId());
			return codeErrorResponse(model, HttpStatus.FORBIDDEN);
		}

		return introspectToken(model, token, tokenTypeHint, authClient);
	}

	private String introspectToken(Model model, String token, String tokenTypeHint, ClientDetailsEntity authClient) {
		Map<String, Object> entity;
		if (!StringUtils.hasText(token)) {
			log.error("Token introspection failed; token ('{}') not provided", token);
			entity = introspectUnknownToken();
			return jsonResponse(model, entity);
		}

		if ("refresh_token".equals(tokenTypeHint)) {
			entity = introspectRefreshToken(token, authClient.getScope());
			if (entity != null) {
				return jsonResponse(model, entity);
			} else {
				entity = introspectAccessToken(token, authClient.getScope());
			}
		} else if (tokenTypeHint.equals("access_token")) {
			entity = introspectAccessToken(token, authClient.getScope());
			if (entity != null) {
				return jsonResponse(model, entity);
			} else {
				entity = introspectRefreshToken(token, authClient.getScope());
			}
		} else {
			entity = introspectAccessToken(token, authClient.getScope());
			if (entity != null) {
				return jsonResponse(model, entity);
			} else {
				entity = introspectRefreshToken(token, authClient.getScope());
			}
		}

		if (entity == null) {
			entity = introspectUnknownToken();
		}
		return jsonResponse(model, entity);
	}

	private Map<String, Object> introspectUnknownToken() {
		return ImmutableMap.of(IntrospectionResultAssembler.ACTIVE, false);
	}

	private Map<String, Object> introspectAccessToken(String token, Set<String> callerScopes) {
		try {
			// check access tokens first (includes ID tokens)
			OAuth2AccessTokenEntity accessToken = tokenServices.readAccessToken(token);
			ClientDetailsEntity tokenClient = accessToken.getClient();

			// get the user information of the user that authorized this token in the first place
			String userName = accessToken.getAuthenticationHolder().getAuthentication().getName();
			UserInfo user = userInfoService.get(userName, tokenClient.getClientId(),
					callerScopes, accessToken.getAuthenticationHolder().getUserAuth());
			return introspectionResultAssembler.assembleFrom(accessToken, user, callerScopes);
		} catch (InvalidTokenException e) {
			return null;
		}
	}

	private Map<String, Object> introspectRefreshToken(String token, Set<String> callerScopes) {
		try {
			OAuth2RefreshTokenEntity refreshToken = tokenServices.getRefreshToken(token);
			ClientDetailsEntity tokenClient = refreshToken.getClient();

			// get the user information of the user that authorized this token in the first place
			String userName = refreshToken.getAuthenticationHolder().getAuthentication().getName();
			UserInfo user = userInfoService.get(userName, tokenClient.getClientId(), callerScopes,
					refreshToken.getAuthenticationHolder().getUserAuth());
			return introspectionResultAssembler.assembleFrom(refreshToken, user, callerScopes);
		} catch (InvalidTokenException e2) {
			return null;
		}
	}

	private String codeErrorResponse(Model model, HttpStatus code) {
		model.addAttribute(HttpCodeView.CODE, code);
		return HttpCodeView.VIEWNAME;
	}

	private String jsonResponse(Model model, Map<String, Object> entity) {
		model.addAttribute(JsonEntityView.ENTITY, entity);
		return JsonEntityView.VIEWNAME;
	}

}
