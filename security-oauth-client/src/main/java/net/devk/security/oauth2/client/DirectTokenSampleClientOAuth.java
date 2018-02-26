package net.devk.security.oauth2.client;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DirectTokenSampleClientOAuth {

	private static Logger logger = LoggerFactory.getLogger(DirectTokenSampleClientOAuth.class);

	private static final Client client = ClientBuilder.newClient();

	private static final String SAMPLE_RESOURCE_SERVER = "http://localhost:9080/services/rest/applicants";
	private static final String OAUTH_SERVER = "http://localhost:9080/oauth2/";
	private static final String OAUTH_TOKEN_ENDPOINT = OAUTH_SERVER + "api/token";

	public static void main(String[] args) throws Exception {

		// makeEndToEndWithDirectTokenRequest("1779fef73e68f09cd6dc69c311c5fed7");
		makeFailResourceRequest();
		makeEndToEndWithDirectTokenRequest();

	}

	private static OAuthAccessTokenResponse makeDirectTokenRequest()
			throws OAuthSystemException, OAuthProblemException {

		OAuthClientRequest request = OAuthClientRequest.tokenLocation(OAUTH_TOKEN_ENDPOINT)
				.setGrantType(GrantType.PASSWORD).setClientId(Params.SAMPLE_CLIENT_ID)
				.setClientSecret(Params.SAMPLE_CLIENT_SECRET).setUsername(Params.SAMPLE_USER_NAME)
				.setPassword(Params.SAMPLE_PASSWORD).buildBodyMessage();

		OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
		OAuthAccessTokenResponse oauthResponse = oAuthClient.accessToken(request);

		logger.info(String.format("access token: %s", oauthResponse.getAccessToken()));
		logger.info(String.format("expires in : %s ", oauthResponse.getExpiresIn()));
		logger.info(String.format("token type : %s ", oauthResponse.getTokenType()));
		logger.info(String.format("body : %s ", oauthResponse.getBody()));
		logger.info(String.format("refresh token : %s ", oauthResponse.getRefreshToken()));
		logger.info(String.format("scope : %s ", oauthResponse.getScope()));
		logger.info(String.format("response code : %s ", oauthResponse.getResponseCode()));

		return oauthResponse;
	}

	private static Response makeFailResourceRequest() throws URISyntaxException {
		WebTarget target = client.target(new URI(SAMPLE_RESOURCE_SERVER));
		Response response = target.request(MediaType.TEXT_HTML).get();
		System.out.println(response.getStatus());
		logger.info(String.format("response status : %d", response.getStatus()));
		response.close();
		return response;
	}

	private static void makeEndToEndWithDirectTokenRequest()
			throws OAuthSystemException, OAuthProblemException, MalformedURLException, URISyntaxException {
		OAuthAccessTokenResponse oauthResponse = makeDirectTokenRequest();
		String accessToken = oauthResponse.getAccessToken();
		makeEndToEndWithDirectTokenRequest(accessToken);
	}

	private static void makeEndToEndWithDirectTokenRequest(String token)
			throws OAuthSystemException, OAuthProblemException, MalformedURLException, URISyntaxException {
		URL restUrl = new URL(SAMPLE_RESOURCE_SERVER);
		WebTarget target = client.target(restUrl.toURI());
		Response response = target.request(MediaType.APPLICATION_JSON)
				.header(OAuth.HeaderType.AUTHORIZATION, "Bearer " + token).header("pageNumber", 0)
				.header("pageSize", 10).get();
		logger.info(String.format("response status : %d", response.getStatus()));
	}

}
