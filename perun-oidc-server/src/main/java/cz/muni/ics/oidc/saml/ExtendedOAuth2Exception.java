package cz.muni.ics.oidc.saml;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

public class ExtendedOAuth2Exception extends OAuth2Exception {

    private final String errorCode;

    public ExtendedOAuth2Exception(String errorCode, String msg) {
        super(msg);
        this.errorCode = errorCode;
    }

    @Override
    public String getOAuth2ErrorCode() {
        return errorCode;
    }
}
