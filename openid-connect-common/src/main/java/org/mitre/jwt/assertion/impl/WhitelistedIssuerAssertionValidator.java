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

package org.mitre.jwt.assertion.impl;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import org.mitre.jwt.assertion.AbstractAssertionValidator;
import org.mitre.jwt.assertion.AssertionValidator;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Checks to see if the assertion has been signed by a particular authority available from a whitelist
 * @author jricher
 */
public class WhitelistedIssuerAssertionValidator extends AbstractAssertionValidator implements AssertionValidator {

	private static Logger logger = LoggerFactory.getLogger(WhitelistedIssuerAssertionValidator.class);

	/**
	 * Map of issuer -> JWKSetUri
	 */
	private Map<String, String> whitelist = new HashMap<>();
	private JWKSetCacheService jwkCache;

	public Map<String, String> getWhitelist() {
		return whitelist;
	}

	public void setWhitelist(Map<String, String> whitelist) {
		this.whitelist = whitelist;
	}

	public JWKSetCacheService getJwkCache() {
		return jwkCache;
	}

	public void setJwkCache(JWKSetCacheService jwkCache) {
		this.jwkCache = jwkCache;
	}

	@Override
	public boolean isValid(JWT assertion) {
		String issuer = extractIssuer(assertion);
		if (StringUtils.isEmpty(issuer)) {
			logger.debug("No issuer for assertion, rejecting");
			return false;
		} else if (!whitelist.containsKey(issuer)) {
			logger.debug("Issuer is not in whitelist, rejecting");
			return false;
		}

		String jwksUri = whitelist.getOrDefault(issuer, null);
		if (jwksUri == null) {
			return false;
		}

		JWTSigningAndValidationService validator = jwkCache.getValidator(jwksUri);

		return validator.validateSignature((SignedJWT) assertion);
	}

}
