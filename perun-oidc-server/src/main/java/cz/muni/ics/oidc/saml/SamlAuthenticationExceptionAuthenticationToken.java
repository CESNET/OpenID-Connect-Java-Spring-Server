/* Copyright 2009 Vladimir Schäfer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package cz.muni.ics.oidc.saml;

import java.security.Principal;
import java.util.Collections;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.StatusCode;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.saml.SAMLStatusException;

@Getter
@ToString
@EqualsAndHashCode(callSuper = true)
@Slf4j
public class SamlAuthenticationExceptionAuthenticationToken extends AbstractAuthenticationToken {

    private static final Principal PRINCIPAL = new SamlAuthenticationExceptionPrincipal();
    public static final SimpleGrantedAuthority ROLE_EXCEPTION = new SimpleGrantedAuthority("ROLE_EXCEPTION");
    private final Exception causeException;

    public SamlAuthenticationExceptionAuthenticationToken(Exception causeException) {
        super(Collections.singleton(ROLE_EXCEPTION));
        this.causeException = causeException;
    }

    @Override
    public Object getCredentials() {
        return "EXCEPTION_IN_SAML_AUTHENTICATION";
    }

    @Override
    public Object getPrincipal() {
        return PRINCIPAL;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void eraseCredentials() { }

    public OAuth2Exception createOAuth2Exception() {
        if (causeException != null) {
            Throwable t = causeException;
            while (t.getCause() != null) {
                log.warn("OAuth2 exception from SAML translation: {} - {}", t.getClass().getSimpleName(), t.getMessage());
                t = t.getCause();
            }
            if (t instanceof InsufficientAuthenticationException) {
                return new ExtendedOAuth2Exception("unmet_authentication_requirements", t.getMessage());
            }
            if (t instanceof SAMLStatusException) {
                String code = ((SAMLStatusException) t).getStatusCode();
                if (StatusCode.NO_AUTHN_CONTEXT_URI.equalsIgnoreCase(code)) {
                    return new ExtendedOAuth2Exception("unmet_authentication_requirements", t.getMessage());
                }
            }
            return new OAuth2Exception(t.getMessage());
        }
        //TODO: handle
        return new OAuth2Exception("");
    }
}
