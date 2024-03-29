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
package cz.muni.ics.openid.connect.service;

import cz.muni.ics.oauth2.model.SavedUserAuthentication;
import cz.muni.ics.openid.connect.model.UserInfo;
import java.util.Set;
import org.springframework.security.saml.SAMLCredential;

/**
 * Interface for UserInfo service
 *
 * @author Michael Joseph Walsh
 *
 */
public interface UserInfoService {

	UserInfo get(String username, String clientId, Set<String> scope, SavedUserAuthentication userAuthentication);

	UserInfo get(String username, String clientId, Set<String> scope, SAMLCredential samlCredential);

	UserInfo get(String username, String clientId, Set<String> scope);

}
