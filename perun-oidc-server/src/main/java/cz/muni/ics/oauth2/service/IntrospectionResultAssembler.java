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
package cz.muni.ics.oauth2.service;

import cz.muni.ics.oauth2.model.OAuth2AccessTokenEntity;
import cz.muni.ics.oauth2.model.OAuth2RefreshTokenEntity;
import cz.muni.ics.openid.connect.model.UserInfo;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.Set;
import javax.swing.text.DateFormatter;

/**
 * Strategy interface for assembling a token introspection result.
 */
public interface IntrospectionResultAssembler {

	String ACTIVE = "active";
	String SCOPE = "scope";
	String CLIENT_ID = "client_id";
	String USERNAME = "username";
	String TOKEN_TYPE = "token_type";
	String EXP = "exp";
	String IAT = "iat";
	String NBF = "nbf";
	String SUB = "sub";
	String AUD = "aud";
	String ISS = "iss";
	String JTI = "jti";

	String ACR = "acr";
	String AUTH_TIME = "auth_time";
	String SCOPE_SEPARATOR = " ";


	/**
	 * Assemble a token introspection result from the given access token and user info.
	 *
	 * @param token the access token
	 * @param introspectionRequesterScopes the scopes the client is authorized for
	 * @return the token introspection result
	 */
	Map<String, Object> assembleFrom(OAuth2AccessTokenEntity token, Set<String> introspectionRequesterScopes);

	/**
	 * Assemble a token introspection result from the given refresh token and user info.
	 *
	 * @param token the refresh token
	 * @param introspectionRequesterScopes the scopes the client is authorized for
	 * @return the token introspection result
	 */
	Map<String, Object> assembleFrom(OAuth2RefreshTokenEntity token, Set<String> introspectionRequesterScopes);

}
