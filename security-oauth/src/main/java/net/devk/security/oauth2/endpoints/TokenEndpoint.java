package net.devk.security.oauth2.endpoints;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.TokenType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.devk.security.oauth2.storage.SecurityCodeStorage;

@Path("/token")
public class TokenEndpoint {

	public static final String INVALID_CLIENT_DESCRIPTION = "Client authentication failed "
			+ "(e.g., unknown client, no client " + "authentication included, or unsupported "
			+ "authentication method).";

	private static final String DEFAULT_EXPIRE_VALUE = "3600";

	private static final Logger logger = LoggerFactory.getLogger(TokenEndpoint.class);

	@Inject
	private SecurityCodeStorage securityCodeStorage;

	@POST
	@Consumes("application/x-www-form-urlencoded")
	@Produces("application/json")
	public Response authorize(@Context HttpServletRequest request) throws OAuthSystemException {

		OAuthTokenRequest oauthRequest = null;

		OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());

		try {
			oauthRequest = new OAuthTokenRequest(request);

			logRequest(oauthRequest);

			// checking client id
			if (!securityCodeStorage.isValidClientId(oauthRequest.getClientId())) {
				return buildInvalidClientIdResponse();
			}

			// checking client secret
			if (!securityCodeStorage.isValidClientSecret(oauthRequest.getClientSecret())) {
				return buildInvalidClientSecretResponse();
			}

			String accessToken = null;
			String refreshToken = null;

			final String oauthGrantType = oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE);

			// checking grant types
			if (oauthGrantType.equals(GrantType.AUTHORIZATION_CODE.toString())) {
				if (!securityCodeStorage.isValidAuthorizationCode(oauthRequest.getParam(OAuth.OAUTH_CODE))) {
					return buildBadAuthCodeResponse();
				}
				refreshToken = oauthIssuerImpl.refreshToken();
			} else if (oauthGrantType.equals(GrantType.PASSWORD.toString())) {
				if (!securityCodeStorage.isValidUser(oauthRequest.getUsername(), oauthRequest.getPassword())) {
					return buildInvalidUserPassResponse();
				}
				refreshToken = oauthIssuerImpl.refreshToken();
			} else if (oauthGrantType.equals(GrantType.REFRESH_TOKEN.toString())) {
				refreshToken = oauthIssuerImpl.refreshToken();
			}
			// does redirect URL need to be checked?

			accessToken = oauthIssuerImpl.accessToken();
			securityCodeStorage.addToken(accessToken);

			OAuthResponse response = OAuthASResponse.tokenResponse(HttpServletResponse.SC_OK)
					.setTokenType(TokenType.BEARER.toString()).setAccessToken(accessToken).setRefreshToken(refreshToken)
					.setExpiresIn(DEFAULT_EXPIRE_VALUE).buildJSONMessage();

			return Response.status(response.getResponseStatus()).entity(response.getBody()).build();

		} catch (OAuthProblemException e) {
			logger.error(e.getMessage());
			OAuthResponse res = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST).error(e)
					.buildJSONMessage();
			return Response.status(res.getResponseStatus()).entity(res.getBody()).build();
		}
	}

	private void logRequest(OAuthTokenRequest request) {
		logger.info("ClientID : {}", request.getClientId());
		logger.info("ClientSecret : {}", request.getClientSecret());
		logger.info("Code : {}", request.getCode());
		logger.info("GrantType : {}", request.getGrantType());
		logger.info("Username : {}", request.getUsername());
		logger.info("Password : {}", request.getPassword());
		logger.info("Redirect URI : {}", request.getRedirectURI());
		logger.info("Refresh Token : {}", request.getRefreshToken());
		for (String scope : request.getScopes()) {
			logger.info("Scope : {}", scope);
		}
	}

	@GET
	@Path("/{token}")
	public Response exists(@PathParam("token") String token) {
		if (securityCodeStorage.isValidToken(token)) {
			return Response.status(Status.OK).build();
		} else {
			return Response.status(Status.NOT_FOUND).build();
		}
	}

	private Response buildInvalidClientIdResponse() throws OAuthSystemException {
		OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
				.setError(OAuthError.TokenResponse.INVALID_CLIENT).setErrorDescription(INVALID_CLIENT_DESCRIPTION)
				.buildJSONMessage();
		return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
	}

	private Response buildInvalidClientSecretResponse() throws OAuthSystemException {
		OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
				.setError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).setErrorDescription(INVALID_CLIENT_DESCRIPTION)
				.buildJSONMessage();
		return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
	}

	private Response buildBadAuthCodeResponse() throws OAuthSystemException {
		OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
				.setError(OAuthError.TokenResponse.INVALID_GRANT).setErrorDescription("invalid authorization code")
				.buildJSONMessage();
		return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
	}

	private Response buildInvalidUserPassResponse() throws OAuthSystemException {
		OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
				.setError(OAuthError.TokenResponse.INVALID_GRANT).setErrorDescription("invalid username or password")
				.buildJSONMessage();
		return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
	}

}