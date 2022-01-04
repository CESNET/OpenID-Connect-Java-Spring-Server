<%@ page contentType="text/html; charset=utf-8" pageEncoding="utf-8" trimDirectiveWhitespaces="true" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.List" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/common"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>

<c:set var="baseURL" value="${baseURL}"/>
<c:set var="samlResourcesURL" value="${samlResourcesURL}"/>
<%

List<String> cssLinks = new ArrayList<>();
pageContext.setAttribute("cssLinks", cssLinks);

%>

<spring:message code="login_failure_title" var="title"/>
<t:header title="${title}" reqURL="${reqURL}" baseURL="${baseURL}" cssLinks="${cssLinks}" theme="${theme}"/>

<div id="head">
    <h3><i class="glyphicon glyphicon-exclamation-sign text-danger"></i>${' '}<spring:message code="unhandled_exception"/></h3>
</div>

</div> <%-- header --%>

<div id="content">
    <br>
    <div>
        <div class="row error-row">
            <div class="col-md-3 font-weight-bold">
                <strong><spring:message code="error_id"/>${':'}</strong>
            </div>
            <div class="col-md-9">
                ${errorId}
            </div>
        </div>
        <div class="row error-row">
            <div class="col-md-3 font-weight-bold">
                <strong><spring:message code="error_message"/>${':'}</strong>
            </div>
            <div class="col-md-9">
                ${message}
            </div>
        </div>
        <div class="row error-row">
            <div class="col-md-3 font-weight-bold">
                <strong><spring:message code="caused_by"/>${':'}</strong>
            </div>
            <div class="col-md-9">
                ${causedBy}
            </div>
        </div>
    </div>
    <br>
    <a href="error/report?errorId=${errorId}">
        <button type="button" class="btn btn-secondary"><spring:message code="send_error_report"/></button>
    </a>
</div>

</div><!-- ENDWRAP -->

<t:footer baseURL="${baseURL}" theme="${theme}"/>








