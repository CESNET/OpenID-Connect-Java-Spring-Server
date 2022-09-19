package cz.muni.ics.oidc.saml;

import static cz.muni.ics.oidc.server.filters.AuthProcFilterConstants.PARAM_PROMPT;
import static cz.muni.ics.oidc.server.filters.AuthProcFilterConstants.PROMPT_LOGIN;
import static cz.muni.ics.oidc.server.filters.AuthProcFilterConstants.PROMPT_SELECT_ACCOUNT;

import javax.servlet.ServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

@Slf4j
public class PerunSamlUtils {

    public static boolean needsReAuthByPrompt(ServletRequest request) {
        String prompt = request.getParameter(PARAM_PROMPT);
        boolean res = (StringUtils.hasText(prompt) && (PROMPT_LOGIN.equalsIgnoreCase(prompt)
            || PROMPT_SELECT_ACCOUNT.equalsIgnoreCase(prompt)));
        log.debug("requires reAuth by prompt - {}", res);
        return res;
    }

}
