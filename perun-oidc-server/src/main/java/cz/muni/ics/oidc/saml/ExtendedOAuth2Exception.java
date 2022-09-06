package cz.muni.ics.oidc.saml;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.StringUtils;

public class ExtendedOAuth2Exception extends OAuth2Exception {

    public static final String ERROR_UNMET_AUTHENTICATION_REQUIREMENTS = "unmet_authentication_requirements";

    public static final String KEY_ERROR_CODE = "errorCode";
    public static final String KEY_ERROR_DESCRIPTION = "errorDescription";

    private final String errorCode;

    public ExtendedOAuth2Exception(String errorCode, String msg) {
        super(msg);
        this.errorCode = errorCode;
    }

    public ExtendedOAuth2Exception(String errorCode, String msg, Throwable t) {
        super(msg, t);
        this.errorCode = errorCode;
    }

    @Override
    public int getHttpErrorCode() {
        if (ERROR_UNMET_AUTHENTICATION_REQUIREMENTS.equals(this.errorCode)) {
            return HttpStatus.FORBIDDEN.value();
        }
        return super.getHttpErrorCode();
    }

    public static ExtendedOAuth2Exception deserialize(String strJson) {
        if (!StringUtils.hasText(strJson)) {
            return null;
        }
        JsonObject json = (JsonObject) JsonParser.parseString(strJson);
        String errorCode = json.get(KEY_ERROR_CODE).getAsString();
        String errorMessage = json.get(KEY_ERROR_DESCRIPTION).getAsString();
        return new ExtendedOAuth2Exception(errorCode, errorMessage);
    }

    public static String serialize(ExtendedOAuth2Exception o) {
        if (o == null) {
            return null;
        }
        JsonObject object = new JsonObject();
        object.addProperty(KEY_ERROR_CODE, o.getOAuth2ErrorCode());
        object.addProperty(KEY_ERROR_DESCRIPTION, o.getMessage());
        return object.toString();
    }

    @Override
    public String getOAuth2ErrorCode() {
        return errorCode;
    }

}
