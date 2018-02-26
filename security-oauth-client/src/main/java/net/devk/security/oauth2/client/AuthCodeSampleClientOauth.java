package net.devk.security.oauth2.client;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

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
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.json.JSONException;
import org.json.JSONObject;

public class AuthCodeSampleClientOauth {

	private static final String SAMPLE_RESOURCE_SERVER = "http://localhost:9080/services/rest/applicants";
	private static final String OAUTH_SERVER = "http://localhost:9080/oauth2/";
	private static final String OAUTH_TOKEN_ENDPOINT = OAUTH_SERVER + "api/token";
	private static final String OAUTH_AUTH_ENDPOINT = OAUTH_SERVER + "api/auth";
	private static final String OAUTH_AUTH_REDIRECT = OAUTH_SERVER + "api/redirect";
	private static Client client = ClientBuilder.newClient();

	public static void main(String[] args) throws Exception {

		makeFailResourceRequest();
		makeEndToEndWithAuthCode();

	}

	private static void makeFailResourceRequest() throws URISyntaxException {
		WebTarget target = client.target(new URI(SAMPLE_RESOURCE_SERVER));
		Response response = target.request(MediaType.TEXT_HTML).get();
		System.out.println(response.getStatus());
		response.close();
	}

	private static Response makeAuthCodeRequest()
			throws OAuthSystemException, MalformedURLException, URISyntaxException {

		OAuthClientRequest request = OAuthClientRequest.authorizationLocation(OAUTH_AUTH_ENDPOINT)
				.setClientId(Params.SAMPLE_CLIENT_ID).setRedirectURI(OAUTH_AUTH_REDIRECT)
				.setResponseType(ResponseType.CODE.toString()).setState("csrf_token").buildQueryMessage();

		WebTarget target = client.target(new URI(request.getLocationUri()));
		Response response = target.request(MediaType.TEXT_HTML).get();

		System.out.println(response.getLocation());

		return response;
	}

	private static OAuthAccessTokenResponse makeTokenRequestWithAuthCode(String authCode)
			throws OAuthProblemException, OAuthSystemException {

		OAuthClientRequest request = OAuthClientRequest.tokenLocation(OAUTH_TOKEN_ENDPOINT)
				.setClientId(Params.SAMPLE_CLIENT_ID).setClientSecret(Params.SAMPLE_CLIENT_SECRET)
				.setGrantType(GrantType.AUTHORIZATION_CODE).setCode(authCode).setRedirectURI(OAUTH_AUTH_REDIRECT)
				.buildBodyMessage();

		OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

		OAuthAccessTokenResponse oauthResponse = oAuthClient.accessToken(request);

		System.out.println("Access Token: " + oauthResponse.getAccessToken());
		System.out.println("Expires In: " + oauthResponse.getExpiresIn());

		return oauthResponse;
	}

	public static void makeEndToEndWithAuthCode() throws URISyntaxException {
		try {
			Response response = makeAuthCodeRequest();
			response.close();

			// browser behavior
			Response redirectionByHeaderLocation = client.target(response.getLocation()).request().get();

			String authCode = getAuthCode(redirectionByHeaderLocation);

			OAuthAccessTokenResponse oauthResponse = makeTokenRequestWithAuthCode(authCode);
			String accessToken = oauthResponse.getAccessToken();

			Response res = client.target(new URI(SAMPLE_RESOURCE_SERVER)).request(MediaType.APPLICATION_JSON)
					.header(OAuth.HeaderType.AUTHORIZATION, "Bearer " + accessToken).get();

			System.out.println(res.getStatus());

			String entity = res.readEntity(String.class);

			System.out.println("Response: " + entity);

		} catch (OAuthProblemException | OAuthSystemException | JSONException | MalformedURLException ex) {

			ex.printStackTrace();

		}
	}

	private static String getAuthCode(Response response) throws JSONException {
		JSONObject obj = new JSONObject(response.readEntity(String.class));
		JSONObject qp = obj.getJSONObject("queryParameters");
		String authCode = null;
		if (qp != null) {
			authCode = qp.getString("code");
		}

		return authCode;
	}

}
