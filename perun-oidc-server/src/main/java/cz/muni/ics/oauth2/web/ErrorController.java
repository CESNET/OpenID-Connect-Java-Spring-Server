package cz.muni.ics.oauth2.web;

import cz.muni.ics.oidc.server.configurations.PerunOidcConfig;
import cz.muni.ics.oidc.web.WebHtmlClasses;
import cz.muni.ics.oidc.web.controllers.ControllerUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
@SessionAttributes("authorizationRequest")
@Slf4j
public class ErrorController {
    private final PerunOidcConfig perunOidcConfig;
    private final WebHtmlClasses htmlClasses;

    @Autowired
    public ErrorController(PerunOidcConfig perunOidcConfig, WebHtmlClasses htmlClasses) {
        this.perunOidcConfig = perunOidcConfig;
        this.htmlClasses = htmlClasses;
    }

    @RequestMapping("/error/report")
    public String test(Map<String, Object> model, HttpServletRequest req) {
        ControllerUtils.setPageOptions(model, req, htmlClasses, perunOidcConfig);

        return "errorReport";
    }
}
