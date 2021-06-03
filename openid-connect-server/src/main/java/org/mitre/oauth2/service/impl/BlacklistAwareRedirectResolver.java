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
/**
 *
 */
package org.mitre.oauth2.service.impl;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.stereotype.Component;

import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mitre.oauth2.model.ClientDetailsEntity.AppType.NATIVE;

/**
 *
 * A redirect resolver that knows how to check against the blacklisted URIs
 * for forbidden values. Can be configured to do strict string matching also.
 *
 * @author jricher
 *
 */
@Component("blacklistAwareRedirectResolver")
public class BlacklistAwareRedirectResolver implements RedirectResolver {

	private static final Logger log = LoggerFactory.getLogger(BlacklistAwareRedirectResolver.class);

	@Autowired
	private BlacklistedSiteService blacklistService;

	@Autowired
	private ConfigurationPropertiesBean config;

	private Collection<String> redirectGrantTypes = Arrays.asList("implicit", "authorization_code");
	private boolean matchSubdomains = false;
	private boolean matchPorts = true;
	private boolean strictMatch = true;

	/**
	 * Flag to indicate that requested URIs will match if they are a subdomain of the registered value.
	 *
	 * @param matchSubdomains the flag value to set (default true)
	 */
	public void setMatchSubdomains(boolean matchSubdomains) {
		this.matchSubdomains = matchSubdomains;
	}

	/**
	 * Flag that enables/disables port matching between the requested redirect URI and the registered redirect URI(s).
	 *
	 * @param matchPorts true to enable port matching, false to disable (defaults to true)
	 */
	public void setMatchPorts(boolean matchPorts) {
		this.matchPorts = matchPorts;
	}

	/**
	 * Grant types that are permitted to have a redirect uri.
	 *
	 * @param redirectGrantTypes the redirect grant types to set
	 */
	public void setRedirectGrantTypes(Collection<String> redirectGrantTypes) {
		this.redirectGrantTypes = new HashSet<String>(redirectGrantTypes);
	}

	/**
	 * @return the strictMatch
	 */
	public boolean isStrictMatch() {
		if (config.isHeartMode()) {
			// HEART mode enforces strict matching
			return true;
		} else {
			return strictMatch;
		}
	}

	/**
	 * Set this to true to require exact string matches for all redirect URIs. (Default is false)
	 *
	 * @param strictMatch the strictMatch to set
	 */
	public void setStrictMatch(boolean strictMatch) {
		this.strictMatch = strictMatch;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.oauth2.provider.endpoint.RedirectResolver#resolveRedirect(java.lang.String, org.springframework.security.oauth2.provider.ClientDetails)
	 */
	@Override
	public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {
		Set<String> authorizedGrantTypes = client.getAuthorizedGrantTypes();
		if (authorizedGrantTypes.isEmpty()) {
			throw new InvalidGrantException("A client must have at least one authorized grant type.");
		}
		if (!containsRedirectGrantType(authorizedGrantTypes)) {
			throw new InvalidGrantException(
				"A redirect_uri can only be used by implicit or authorization_code grant types.");
		}

		Set<String> registeredRedirectUris = client.getRegisteredRedirectUri();
		if (registeredRedirectUris == null || registeredRedirectUris.isEmpty()) {
			throw new InvalidRequestException("At least one redirect_uri must be registered with the client.");
		}

		ClientDetailsEntity cde = (ClientDetailsEntity) client;

		String redirect = obtainMatchingRedirect(registeredRedirectUris, requestedRedirect, cde.getApplicationType());

		if (blacklistService.isBlacklisted(redirect)) {
			// don't let it go through
			throw new InvalidRequestException("The supplied redirect_uri is not allowed on this server.");
		} else {
			// not blacklisted, passed the parent test, we're fine
			return redirect;
		}
	}

	/**
	 * Whether the requested redirect URI "matches" the specified redirect URI. For a URL, this implementation tests if
	 * the user requested redirect starts with the registered redirect, so it would have the same host and root path if
	 * it is an HTTP URL. The port, userinfo, query params also matched. Request redirect uri path can include
	 * additional parameters which are ignored for the match
	 * <p>
	 * For other (non-URL) cases, such as for some implicit clients, the redirect_uri must be an exact match.
	 *
	 * @param requestedRedirect The requested redirect URI.
	 * @param redirectUri The registered redirect URI.
	 * @param applicationType
	 * @return Whether the requested redirect URI "matches" the specified redirect URI.
	 */
	protected boolean redirectMatches(String requestedRedirect, String redirectUri,
									  ClientDetailsEntity.AppType applicationType)
	{
		UriComponents requestedRedirectUri = UriComponentsBuilder.fromUriString(requestedRedirect).build();
		UriComponents registeredRedirectUri = UriComponentsBuilder.fromUriString(redirectUri).build();

		boolean schemeMatch = isEqual(registeredRedirectUri.getScheme(), requestedRedirectUri.getScheme());
		boolean userInfoMatch = isEqual(registeredRedirectUri.getUserInfo(), requestedRedirectUri.getUserInfo());
		boolean hostMatch = hostMatches(registeredRedirectUri.getHost(), requestedRedirectUri.getHost());
		boolean portMatch = true;
		if (!NATIVE.equals(applicationType)) {
			portMatch = !matchPorts || registeredRedirectUri.getPort() == requestedRedirectUri.getPort();
		}
		boolean pathMatch = true;
		boolean queryParamMatch = true;
		if (strictMatch) {
			pathMatch = isEqual(registeredRedirectUri.getPath(),
				StringUtils.cleanPath(requestedRedirectUri.getPath()));
			queryParamMatch = matchQueryParams(registeredRedirectUri.getQueryParams(),
				requestedRedirectUri.getQueryParams());
		}

		return schemeMatch && userInfoMatch && hostMatch && portMatch && pathMatch && queryParamMatch;
	}

	/**
	 * @param grantTypes some grant types
	 * @return true if the supplied grant types includes one or more of the redirect types
	 */
	private boolean containsRedirectGrantType(Set<String> grantTypes) {
		for (String type : grantTypes) {
			if (redirectGrantTypes.contains(type)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Attempt to match one of the registered URIs to the that of the requested one.
	 *
	 * @param redirectUris the set of the registered URIs to try and find a match. This cannot be null or empty.
	 * @param requestedRedirect the URI used as part of the request
	 * @param applicationType
	 * @return redirect uri
	 * @throws RedirectMismatchException if no match was found
	 */
	private String obtainMatchingRedirect(Set<String> redirectUris, String requestedRedirect,
										  ClientDetailsEntity.AppType applicationType)
	{
		Assert.notEmpty(redirectUris, "Redirect URIs cannot be empty");

		if (redirectUris.size() == 1 && requestedRedirect == null) {
			return redirectUris.iterator().next();
		}

		for (String redirectUri : redirectUris) {
			if (requestedRedirect != null && redirectMatches(requestedRedirect, redirectUri, applicationType)) {
				// Initialize with the registered redirect-uri
				UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(redirectUri);
				UriComponents requestedRedirectUri = UriComponentsBuilder.fromUriString(requestedRedirect).build();

				if (this.matchSubdomains) {
					redirectUriBuilder.host(requestedRedirectUri.getHost());
				}
				if (!this.matchPorts || NATIVE.equals(applicationType)) {
					redirectUriBuilder.port(requestedRedirectUri.getPort());
				}
				if (!this.strictMatch) {
					redirectUriBuilder.path(requestedRedirectUri.getPath());
				}
				redirectUriBuilder.replaceQuery(requestedRedirectUri.getQuery());		// retain additional params (if any)
				redirectUriBuilder.fragment(null);
				return redirectUriBuilder.build().toUriString();
			}
		}

		throw new RedirectMismatchException("Invalid redirect: " + requestedRedirect
			+ " does not match one of the registered values.");
	}

	/**
	 * Compares two strings but treats empty string or null equal
	 *
	 * @param str1
	 * @param str2
	 * @return true if strings are equal, false otherwise
	 */
	private boolean isEqual(String str1, String str2) {
		if (StringUtils.isEmpty(str1)) {
			return StringUtils.isEmpty(str2);
		} else {
			return str1.equals(str2);
		}
	}

	/**
	 * Check if host matches the registered value.
	 *
	 * @param registered the registered host. Can be null.
	 * @param requested the requested host. Can be null.
	 * @return true if they match
	 */
	protected boolean hostMatches(String registered, String requested) {
		if (matchSubdomains) {
			return isEqual(registered, requested) || (requested != null && requested.endsWith("." + registered));
		}
		return isEqual(registered, requested);
	}

	/**
	 * Checks whether the registered redirect uri query params key and values contains match the requested set
	 *
	 * The requested redirect uri query params are allowed to contain additional params which will be retained
	 *
	 * @param registeredRedirectUriQueryParams
	 * @param requestedRedirectUriQueryParams
	 * @return whether the params match
	 */
	private boolean matchQueryParams(MultiValueMap<String, String> registeredRedirectUriQueryParams,
									 MultiValueMap<String, String> requestedRedirectUriQueryParams)
	{
		for (String key : registeredRedirectUriQueryParams.keySet()) {
			List<String> registeredRedirectUriQueryParamsValues = registeredRedirectUriQueryParams.get(key);
			List<String> requestedRedirectUriQueryParamsValues = requestedRedirectUriQueryParams.get(key);

			if (!registeredRedirectUriQueryParamsValues.equals(requestedRedirectUriQueryParamsValues)) {
				return false;
			}
		}

		return true;
	}

}
