package net.devk.security.oauth2.storage;

public interface SecurityCodeStorage {

	public void addToken(String token);

	public boolean isValidToken(String token);

	public void addAuthorizationCode(String token);

	public boolean isValidAuthorizationCode(String authCode);

	public boolean isValidClientId(String clientId);

	public boolean isValidClientSecret(String clientSecret);

	public boolean isValidUser(String username, String password);

}