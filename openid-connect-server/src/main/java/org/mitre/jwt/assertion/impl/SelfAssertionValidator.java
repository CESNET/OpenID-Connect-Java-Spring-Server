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

import org.mitre.jwt.assertion.AbstractAssertionValidator;
import org.mitre.jwt.assertion.AssertionValidator;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.util.StringUtils;

/**
 * Validates all assertions generated by this server
 *
 * @author jricher
 */
@Component("selfAssertionValidator")
public class SelfAssertionValidator extends AbstractAssertionValidator implements AssertionValidator {

	private static final Logger logger = LoggerFactory.getLogger(SelfAssertionValidator.class);

	private final ConfigurationPropertiesBean config;
	private final JWTSigningAndValidationService jwtService;

	@Autowired
	public SelfAssertionValidator(ConfigurationPropertiesBean config, JWTSigningAndValidationService jwtService) {
		this.config = config;
		this.jwtService = jwtService;
	}

	@Override
	public boolean isValid(JWT assertion) {
		String issuer = extractIssuer(assertion);
		if (StringUtils.isEmpty(issuer)) {
			logger.debug("No issuer for assertion, rejecting");
			return false;
		} else if (!issuer.equals(config.getIssuer())) {
			logger.debug("Issuer is not the same as this server, rejecting");
			return false;
		}

		return jwtService.validateSignature((SignedJWT) assertion);
	}

}
