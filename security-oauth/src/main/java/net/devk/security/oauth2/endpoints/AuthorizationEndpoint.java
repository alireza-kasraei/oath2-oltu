package net.devk.security.oauth2.endpoints;

import java.net.URI;
import java.net.URISyntaxException;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;

import net.devk.security.oauth2.storage.SecurityCodeStorage;

@Path("/authz")
public class AuthorizationEndpoint {

	@Inject
	private SecurityCodeStorage securityCodeStorage;

	@GET
	public Response authorize(@Context HttpServletRequest request) throws URISyntaxException, OAuthSystemException {

		OAuthAuthzRequest oauthRequest = null;

		OAuthIssuerImpl oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());

		try {
			oauthRequest = new OAuthAuthzRequest(request);

			String responseType = oauthRequest.getParam(OAuth.OAUTH_RESPONSE_TYPE);

			String clientId = oauthRequest.getParam(OAuth.OAUTH_CLIENT_ID);
			// TODO FIXME validate clientId

			OAuthASResponse.OAuthAuthorizationResponseBuilder builder = OAuthASResponse.authorizationResponse(request,
					HttpServletResponse.SC_FOUND);

			if (responseType.equals(ResponseType.CODE.toString())) {
				final String authorizationCode = oauthIssuerImpl.authorizationCode();
				securityCodeStorage.addAuthorizationCode(authorizationCode);
				builder.setCode(authorizationCode);
			}

			if (responseType.equals(ResponseType.TOKEN.toString())) {
				final String accessToken = oauthIssuerImpl.accessToken();
				securityCodeStorage.addToken(accessToken);
				builder.setAccessToken(accessToken);
				builder.setTokenType(OAuth.DEFAULT_TOKEN_TYPE.toString());
				builder.setExpiresIn(3600l);
			}

			String redirectURI = oauthRequest.getParam(OAuth.OAUTH_REDIRECT_URI);

			final OAuthResponse response = builder.location(redirectURI).buildQueryMessage();
			URI url = new URI(response.getLocationUri());

			return Response.status(response.getResponseStatus()).location(url).build();

		} catch (OAuthProblemException e) {

			final Response.ResponseBuilder responseBuilder = Response.status(HttpServletResponse.SC_FOUND);

			String redirectUri = e.getRedirectUri();

			if (OAuthUtils.isEmpty(redirectUri)) {
				throw new WebApplicationException(
						responseBuilder.entity("OAuth callback url needs to be provided by client!!!").build());
			}

			final OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_FOUND).error(e)
					.location(redirectUri).buildQueryMessage();
			final URI location = new URI(response.getLocationUri());
			return responseBuilder.location(location).build();

		}
	}
}
