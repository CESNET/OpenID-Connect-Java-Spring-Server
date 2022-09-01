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

package cz.muni.ics.oauth2.web;

import com.google.common.collect.ImmutableSet;
import cz.muni.ics.oauth2.model.ClientDetailsEntity;
import cz.muni.ics.oidc.models.Facility;
import cz.muni.ics.oidc.models.PerunAttributeValue;
import cz.muni.ics.oidc.server.adapters.PerunAdapter;
import java.util.Locale;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.StringUtils;

/**
 *
 * Utility class to enforce OAuth scopes in authenticated requests.
 *
 * @author jricher
 *
 */
public abstract class AuthenticationUtilities {

	public static final Set<String> EU_EAA = Set.of("AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
			"EL", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PT", "RO", "SK", "SI", "ES", "SE", "NO", "IS", "LI", "GB");

	/**
	 * Makes sure the authentication contains the given scope, throws an exception otherwise
	 * @param auth the authentication object to check
	 * @param scope the scope to look for
	 * @throws InsufficientScopeException if the authentication does not contain that scope
	 */
	public static void ensureOAuthScope(Authentication auth, String scope) {
		// if auth is OAuth, make sure we've got the right scope
		if (auth instanceof OAuth2Authentication) {
			OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) auth;
			if (oAuth2Authentication.getOAuth2Request().getScope() == null
					|| !oAuth2Authentication.getOAuth2Request().getScope().contains(scope)) {
				throw new InsufficientScopeException("Insufficient scope", ImmutableSet.of(scope));
			}
		}
	}

	/**
	 * Check to see if the given auth object has ROLE_ADMIN assigned to it or not
	 * @param auth
	 * @return
	 */
	public static boolean isAdmin(Authentication auth) {
		for (GrantedAuthority grantedAuthority : auth.getAuthorities()) {
			if (grantedAuthority.getAuthority().equals("ROLE_ADMIN")) {
				return true;
			}
		}
		return false;
	}


	public static boolean hasRole(Authentication auth, String role) {
		for (GrantedAuthority grantedAuthority : auth.getAuthorities()) {
			if (grantedAuthority.getAuthority().equals(role)) {
				return true;
			}
		}
		return false;

	}

	public static String getJurisdiction(ClientDetailsEntity client) {
		if (!StringUtils.hasText(client.getJurisdiction()) || EU_EAA.contains(client.getJurisdiction())) {
			return "";
		} else if (client.getJurisdiction().length() > 2) {
			if ("EMBL".equalsIgnoreCase(client.getJurisdiction())) {
				return "EMBL";
			}
			return "INT";
		}

		Locale l = new Locale("", client.getJurisdiction());
		return l.getDisplayCountry() + " (" + l.getISO3Country() + ")";
	}

	public static boolean isTestSp(ClientDetailsEntity client, PerunAdapter perunAdapter, String testSpAttrName) {
		if (client == null || !StringUtils.hasText(client.getClientId())) {
			return true;
		}
		Facility facility = perunAdapter.getFacilityByClientId(client.getClientId());
		if (facility == null || facility.getId() == null) {
			return true;
		}

		PerunAttributeValue attrValue = perunAdapter.getFacilityAttributeValue(facility.getId(), testSpAttrName);
		if (attrValue == null) {
			return false;
		} else if (attrValue.valueAsBoolean()) {
			return attrValue.valueAsBoolean();
		}
		return false;
	}

}
