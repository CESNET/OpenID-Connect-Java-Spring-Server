package org.mitre.oauth2.service.impl;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashSet;

public class ServiceUtils {

	public static UserDetails getUserDetails(String decodedClientId, ClientDetailsEntity client, String encodedPassword, ConfigurationPropertiesBean config, GrantedAuthority roleClient) {
		if (config.isHeartMode() || // if we're running HEART mode turn off all client secrets
			(client.getTokenEndpointAuthMethod() != null &&
				(client.getTokenEndpointAuthMethod().equals(ClientDetailsEntity.AuthMethod.PRIVATE_KEY) ||
					client.getTokenEndpointAuthMethod().equals(ClientDetailsEntity.AuthMethod.SECRET_JWT)))) {
			encodedPassword = new BigInteger(512, new SecureRandom()).toString(16);
		}

		Collection<GrantedAuthority> authorities = new HashSet<>(client.getAuthorities());
		authorities.add(roleClient);

		return new User(decodedClientId, encodedPassword, true, true, true, true, authorities);
	}

}
