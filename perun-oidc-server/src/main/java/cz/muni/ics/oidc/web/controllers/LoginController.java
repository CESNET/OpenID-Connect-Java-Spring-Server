package cz.muni.ics.oidc.web.controllers;

import cz.muni.ics.oidc.server.configurations.PerunOidcConfig;
import cz.muni.ics.oidc.web.WebHtmlClasses;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@Slf4j
public class LoginController {

	public static final String MAPPING_SUCCESS = "/login_success";
	public static final String MAPPING_FAILURE = "/login_failure";

	private final WebHtmlClasses htmlClasses;
	private final PerunOidcConfig perunOidcConfig;

	@Autowired
	public LoginController(PerunOidcConfig perunOidcConfig, WebHtmlClasses htmlClasses) {
		this.perunOidcConfig = perunOidcConfig;
		this.htmlClasses = htmlClasses;
	}

	@RequestMapping(value = MAPPING_SUCCESS)
	public String loginSuccess(HttpServletRequest req, Map<String, Object> model) {
		ControllerUtils.setPageOptions(model, req, htmlClasses, perunOidcConfig);
		return "login_success";
	}

	@RequestMapping(value = MAPPING_FAILURE)
	public String loginFailure(HttpServletRequest req, Map<String, Object> model) {
		AuthenticationException ae = (AuthenticationException) req.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);

		UUID errorId = UUID.randomUUID();
		model.put("errorId", errorId.toString());

		if (ae == null) {
			HttpSession session = req.getSession(false);

			if (session != null) {
				ae = (AuthenticationException) req.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
			}
		}

		if (ae != null) {
			model.put("message", ae.getMessage());
			model.put("causedBy", ae.getCause());
		} else {
			model.put("message", "The exception could not be retrieved.");
			model.put("causedBy", "The exception could not be retrieved.");
		}

		log.debug("loginFailure: Exception with ID {}: ", errorId, ae);

		ControllerUtils.setPageOptions(model, req, htmlClasses, perunOidcConfig);
		return "login_failure";
	}

}
