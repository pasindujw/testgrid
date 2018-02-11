/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.testgrid.web.sso;

import org.slf4j.LoggerFactory;
import org.wso2.testgrid.common.exception.TestGridException;
import org.wso2.testgrid.web.api.SSOService;
import org.wso2.testgrid.web.utils.ConfigurationContext;
import org.wso2.testgrid.web.utils.Constants;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class check whether a session exists for the user and do the needfuls accordingly.
 */
public class SSOSessionCheckFilter implements Filter {
    private static final Logger loggertemp = Logger.getLogger("SessionCheck");
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(SSOService.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    /**
     * Check each request's path and do check for SESSION if the path has to be secured.
     * Otherwise allowed
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
        try {
            if(ConfigurationContext.getProperty(Constants.PROPERTYNAME_ENABLE_SSO).equals("false")) {
                filterChain.doFilter(servletRequest, servletResponse);
            }
        } catch (TestGridException e) {
            logger.error("Error occurred while checking if SSO is enabled in Testgrid property file " +
                    Constants.WEB_PROPERTY_FILE_NAME, e);
        }
        String path = ((HttpServletRequest) servletRequest).getRequestURI();
        if (isSecuredAPI(path)) {
            Boolean isSessionValid = ((HttpServletRequest) servletRequest).isRequestedSessionIdValid();
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            Cookie cookies[] = request.getCookies();
            loggertemp.log(Level.INFO,"Path: " + path);
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    loggertemp.log(Level.INFO,cookie.getName()+ ":" + cookie.getValue() + " Session: " + isSessionValid);
                }
            }
            if (!isSessionValid) {
                    loggertemp.log(Level.INFO, "Invalid session");
                HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
                try {
                    httpResponse.sendRedirect(ConfigurationContext.getProperty(Constants.SSO_LOGIN_URL));
                } catch (TestGridException e) {
                    throw new ServletException("Error when reading property SSO_LOGIN_URL");
                }
                return;
            }
            filterChain.doFilter(servletRequest, servletResponse);
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    /**
     * Check if the requested path is a secured API which should be allowed only for logged in users.
     * If SSO is disabled in the property file this will return false for every path.
     * (Property file :  {@link Constants#WEB_PROPERTY_FILE_NAME})
     *
     * @param path Requested URL in String format.
     * @return whether its a securedAPI or not.
     */
    private boolean isSecuredAPI(String path) {
        return !path.startsWith(Constants.LOGIN_URI) &&
                !path.startsWith(Constants.STATIC_DATA_URI) &&
                !path.startsWith(Constants.ACS_URI);
    }

    @Override
    public void destroy() {

    }
}
