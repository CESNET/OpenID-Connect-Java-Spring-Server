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
    <h3>Error report</h3>
</div>

</div> <%-- header --%>

<div id="content">
    <div class="panel panel-default">
        <div class="panel-heading">
            <h3 class="panel-title"><spring:message code="report_errors"/></h3>
        </div>
        <div class="panel-body">

            <form action="error_report_address" method="post" class="form-horizontal">
                <div class="form-group">
                    <label class="col-sm-2 control-label" for="reportId"><spring:message code="error_id"/></label>
                    <div class="col-sm-10">
                        <input name="reportId" type="text" class="form-control" id="reportId" value="${param.errorId}" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label" for="email"><spring:message code="email_address"/></label>
                    <div class="col-sm-10">
                        <input name="email" type="email" class="form-control" id="email" placeholder="Email" required>
                        <span class="help-block">
                            <spring:message code="please_provide_email"/>
                        </span>
                    </div>
                </div>

                <div class="form-group">
                    <div class="col-sm-12">
                        <textarea name="text" class="form-control" rows="3" placeholder="<spring:message code="what_you_did_placeholder"/>"></textarea>
                    </div>
                </div>

                <button type="submit" name="send" class="btn btn-primary"><spring:message code="send"/></button>
            </form>
        </div>
    </div>
</div>

</div><!-- ENDWRAP -->

<t:footer baseURL="${baseURL}" theme="${theme}"/>
