package net.devk.security;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import com.fasterxml.jackson.jaxrs.json.JacksonJaxbJsonProvider;

@ApplicationPath("/api")
public class JaxRsActivator extends Application {

	@Override
	public Set<Class<?>> getClasses() {
		Set<Class<?>> resources = new HashSet<>();

		resources.add(net.devk.security.oauth2.endpoints.AuthorizationEndpoint.class);
		resources.add(net.devk.security.oauth2.endpoints.RedirectEndpoint.class);
		resources.add(net.devk.security.oauth2.endpoints.TokenEndpoint.class);

		resources.add(JacksonJaxbJsonProvider.class);
		return resources;
	}

}
