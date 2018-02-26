package net.devk.security.oauth2.endpoints;

import java.util.List;
import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriInfo;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This endpoint should be in the client to receive the browser redirect and get
 * auth code information
 *
 */
@Path("/redirect")
public class RedirectEndpoint {

	private Logger log = LoggerFactory.getLogger(RedirectEndpoint.class);

	@Context
	HttpHeaders httpHeaders;

	@Context
	UriInfo uriInfo;

	@GET
	public String redirect() {

		JSONObject object = new JSONObject();
		JSONObject headers = new JSONObject();
		JSONObject queryParameteres = new JSONObject();

		String json = "error trying to receive auth code";

		try {
			for (Map.Entry<String, List<String>> entry : httpHeaders.getRequestHeaders().entrySet()) {
				headers.put(entry.getKey(), entry.getValue().get(0));
			}

			object.put("headers", headers);

			for (Map.Entry<String, List<String>> entry : uriInfo.getQueryParameters().entrySet()) {
				queryParameteres.put(entry.getKey(), entry.getValue().get(0));
			}
			object.put("queryParameters", queryParameteres);

			json = object.toString(4);

		} catch (JSONException ex) {

			log.error(ex.getMessage());

		}

		return json;
	}
}
