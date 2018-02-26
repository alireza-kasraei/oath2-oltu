package net.devk.security.oauth2.filter;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.ParameterStyle;
import org.apache.oltu.oauth2.rs.request.OAuthAccessResourceRequest;
import org.apache.oltu.oauth2.rs.response.OAuthRSResponse;

/**
 * Sample Filter for be used in a resource server
 */

public class Oauth2Filter implements Filter {

	private static final String DEFAULT_OAUTH_SERVER_URL = "http://localhost:9080/oauth2/api/token/%s";
	private String oauthServerURL = null;

	@Override
	public void destroy() {
	}

	@Override
	public void init(FilterConfig fConfig) throws ServletException {
		String oauthServerURLConfigParameter = fConfig.getInitParameter("OAUTH_SERVER_URL");
		if (oauthServerURLConfigParameter != null) {
			oauthServerURL = oauthServerURLConfigParameter;
		} else {
			oauthServerURL = DEFAULT_OAUTH_SERVER_URL;
		}
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletResponse res = (HttpServletResponse) response;

		try {

			OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest((HttpServletRequest) request,
					ParameterStyle.HEADER);
			String accessToken = oauthRequest.getAccessToken();

			if (!isValidToken(accessToken)) {

				OAuthResponse oauthResponse = OAuthRSResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
						// .setRealm(RESOURCE_SERVER_NAME)
						.setError(OAuthError.ResourceResponse.INVALID_TOKEN).buildHeaderMessage();

				res.addHeader(OAuth.HeaderType.WWW_AUTHENTICATE,
						oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE));
				res.setStatus(oauthResponse.getResponseStatus());
				res.sendError(oauthResponse.getResponseStatus());
			} else {
				chain.doFilter(request, response);
			}

		} catch (OAuthSystemException | OAuthProblemException e) {

			try {

				OAuthResponse oauthResponse = OAuthRSResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
						// .setRealm(RESOURCE_SERVER_NAME)
						.buildHeaderMessage();

				res.addHeader(OAuth.HeaderType.WWW_AUTHENTICATE,
						oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE));
				res.setStatus(oauthResponse.getResponseStatus());
				res.sendError(oauthResponse.getResponseStatus());

			} catch (OAuthSystemException e1) {

				Logger.getLogger(getClass().getName()).log(Level.SEVERE, "error trying to handle oauth problem", e1);

			}

		}

	}

	private boolean isValidToken(String token) {
		try {

			URL restUrl = new URL(String.format(oauthServerURL, token));
			HttpURLConnection conn = (HttpURLConnection) restUrl.openConnection();
			conn.setRequestMethod("GET");
			conn.disconnect();
			return HttpServletResponse.SC_OK == conn.getResponseCode();
		} catch (Exception e) {
			return false;
		}
	}
}
