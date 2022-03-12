<%@ page contentType="text/html; charset=utf-8" pageEncoding="utf-8"
         import="cz.muni.ics.oidc.server.ga4gh.Ga4ghPassportAndVisaClaimSource"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="ls" tagdir="/WEB-INF/tags/lsaai" %>

<ls:header />
<!-- block container -->
<div class="aas-message">
    <p>
        The service <strong><c:out value="${client.clientName}" /></strong> requires access to your personal data.
        <c:if test="${not empty(client.policyUri)}">
        Please, read the <a target="_blank" href="<c:out value="${client.policyUri}" />">Privacy Policy</a> of the service to learn more about its commitments to protect your data.
        </c:if>
    </p>
</div>
<c:if test="${empty(client.policyUri)}">
<div class="alert alert-warning" role="alert">
    <h6>This service is missing a Privacy Policy document.</h6>
</div>
</c:if>
<c:if test="${getsOfflineAccess}">
<div class="alert alert-warning" role="alert">
    <div><h6>This service requests continuous access to your personal data.</h6>
        <p>
            Normally when you close your browser the service stops fetching your personal data from Life Science Login.
            However, in this case, fetching your personal data continues as it is required for the service to work.
        </p>
    </div>
</div>
</c:if>
<c:if test="${not client.acceptedTos}">
    <div class="alert alert-warning" role="alert">
        <h6>This service has not declared compliance with the <a target="_blank" href="https://lifescience-ri.eu/aai/terms-of-use">Terms of Use for service providers</a> that govern the service's use of Life Science Login.</h6>
    </div>
</c:if>
<form name="confirmationForm" id="allow_consent_form" class="form-group"
          action="${ config.issuer }${ config.issuer.endsWith('/') ? '' : '/' }auth/authorize" method="post">
    <div id="accordion">
        <div class="section">
            <div class="card-header" id="headingOne">
                <h5 class="mb-0">
                    <button class="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseOne" aria-expanded="true" aria-controls="collapseOne">
                        User Information
                    </button>
                </h5>
            </div>
            <c:if test="${not empty scopes}">
                <c:forEach var="scope" items="${scopes}">
                    <c:set var="singleClaim" value="${fn:length(claims[scope.value]) eq 1}" />
                    <div class="card-body">
                        <div class="attribute-row">
                            <div class="attribute">
                                <div class="attribute-name form-check">
                                    <input class="form-check-input" type="checkbox" name="scope_${ fn:escapeXml(scope.value) }" checked="checked"
                                           id="scope_${fn:escapeXml(scope.value)}" value="${fn:escapeXml(scope.value)}">
                                    <label class="form-check-label" for="scope_${fn:escapeXml(scope.value)}">
                                        <spring:message code="${scope.value}"/>
                                    </label>
                                </div>
                            </div>
                            <div class="attribute-values">
                                <c:forEach var="claim" items="${claims[scope.value]}">
                                <div class="attribute-choose">
                                    <div class="attribute-value">
                                        <c:if test="${claim.value.getClass().name eq 'java.util.ArrayList'}">
                                            <c:forEach var="subValue" items="${claim.value}">
                                                <div>
                                                <c:choose>
                                                    <c:when test="${claim.key=='ga4gh_passport_v1'}">
                                                        <code><%= Ga4ghPassportAndVisaClaimSource.parseAndVerifyVisa(
                                                                (String) pageContext.findAttribute("subValue")).getPrettyString() %></code>
                                                    </c:when>
                                                    <c:otherwise>
                                                        <code>${subValue}</code>
                                                    </c:otherwise>
                                                </c:choose>
                                                </div>
                                            </c:forEach>
                                        </c:if>
                                        <c:if test="${not(claim.value.getClass().name eq 'java.util.ArrayList')}">
                                            <c:if test="${scope.value eq 'profile'
                                                          or scope.value eq 'email'
                                                          or scope.value eq 'phone'}">
                                                <strong><spring:message code="${claim.key}"/>:${' '}</strong>
                                            </c:if>
                                            <code>${claim.value}</code>
                                        </c:if>
                                    </div>
                                </div>
                                </c:forEach>
                            </div>
                        </div>
                    </div>
                </c:forEach>
            </c:if>
        </div>
    </div>

    <c:if test="${not empty jurisdiction}">
    <div class="alert alert-danger" role="alert">
        <h6>
            This service is${' '}
            <c:if test="${jurisdiction eq 'INT'}">provided by an international organization. </c:if>
            <c:if test="${jurisdiction ne 'INT'}">in ${jurisdiction}</c:if>
        </h6>
        <p>
            In order to access the requested services, the Life Science Login needs to transfer your personal data to a country outside EU/EEA.
            We cannot guarantee that this country offers an adequately high level of personal data protection as EU/EEA countries.

            <c:if test="${not empty(client.policyUri)}">
                Please, read the <a target="_blank" href="<c:out value="${client.policyUri}" />">Privacy Policy</a> of the service provider to learn more about its commitments to protect your data.
            </c:if>
        </p>
        <div class="form-check">
            <input class="form-check-input" type="checkbox" name="transfer" id="transfer" data-np-checked="1">
            <label class="form-check-label" for="transfer">To continue, consent to the transfer of your personal data.</label>
        </div>
    </div>
    </c:if>
    <div class="outro">
        <p>
            For withdrawing consent, contact <a href="mailto:support@aai.lifescience-ri.eu">support@example.com</a>
        </p>
    </div>
    <div class="footer-buttons">
        <div class="remember">
            <label>Remember:</label>
            <div id="select-amount">
                <select name="remember" id="month" class="btn btn-sm btn-secondary amount">
                    <option value="none">Just this time</option>
                    <option value="until-revoked">Forever</option>
                </select>
            </div>
        </div>
        <div class="consent-button">
            <a id="abort" class="btn btn-danger" href="https://lifescience-ri.eu/index.php?id=409">Abort</a>
            <input type="submit" class="btn btn-primary" value="Consent" id="submit" name="authorize"
                   <c:if test="${not empty jurisdiction}">disabled=""</c:if>
                   onclick="$('#user_oauth_approval').attr('value',true)">
        </div>
    </div>
    <input id="user_oauth_approval" name="user_oauth_approval" value="true" type="hidden" />
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
</form>

<ls:footer />
