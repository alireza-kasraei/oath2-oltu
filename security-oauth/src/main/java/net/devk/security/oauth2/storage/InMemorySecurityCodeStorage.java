package net.devk.security.oauth2.storage;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class InMemorySecurityCodeStorage implements SecurityCodeStorage {

	private Set<String> tokens = new HashSet<String>();
	private Set<String> authorizationCodes = new HashSet<String>();
	private Set<String> clientIds = new HashSet<String>();
	private Set<String> clientSecrets = new HashSet<String>();
	private Map<String, String> users = new HashMap<>();

	public static final String SAMPLE_CLIENT_SECRET = "s@mple_client_s3cr3t";
	public static final String SAMPLE_CLIENT_ID = "sample_client_id";
	public static final String SAMPLE_USER_NAME = "sample_username";
	public static final String SAMPLE_PASSWORD = "sample_password";

	public InMemorySecurityCodeStorage() {
		clientIds.add(SAMPLE_CLIENT_ID);
		clientSecrets.add(SAMPLE_CLIENT_SECRET);
		users.put(SAMPLE_USER_NAME, SAMPLE_PASSWORD);
	}

	public void addToken(String token) {
		tokens.add(token);
	}

	public boolean isValidToken(String token) {
		return tokens.contains(token);
	}

	@Override
	public void addAuthorizationCode(String token) {
		authorizationCodes.add(token);
	}

	@Override
	public boolean isValidAuthorizationCode(String authCode) {
		return authorizationCodes.contains(authCode);
	}

	@Override
	public boolean isValidClientId(String clientId) {
		return clientIds.contains(clientId);
	}

	@Override
	public boolean isValidClientSecret(String clientSecret) {
		return clientSecrets.contains(clientSecret);
	}

	@Override
	public boolean isValidUser(String username, String password) {
		String storedPassword = users.get(username);
		return storedPassword != null && storedPassword.equals(password);
	}

}
