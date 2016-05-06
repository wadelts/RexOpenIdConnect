package com.rexcanium.oidc;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;

/**
 * Retrieves all the configuration information from service
 * providers - for example end-points and KeySets.
 * This information is then used to make calls to the service
 * provider, during authentication requests.
 * 
 * @author wadel
 *
 */
public interface OpenIdConnProviderConfig {

	/**
	 * This will retrieve the configuration data from the Provider.
	 * (This method MUST be called before using this instance.)
	 * 
	 * @return a reference to the instance (this)
	 */
	OpenIdConnProviderConfig initialise();

	URI getAuthorizationEndpointURI();

	URI getTokenEndpointURI();

	URI getUserInfoEndpointURI();

	String getClientID();

	String getClientSecret();

	/**
	 * Retrieve a Public key stored against this Provider.
	 * The Provider uses these keys to sign JWTs, so we need the key to verify each JWT.
	 * 
	 * @param kid The Key ID (supplied by owner of Key) - submit kid="" (empty String) if there is only one key involved for this provider
	 * @return the Key which was used by the Provider to hash the token
	 */
	RSAPublicKey getProviderKey(String kid);

	/**
	 * @return the URI that is sent to Providers when asking for a Code. The Provider will come back to this URI with the Code (by redirecting User's client).
	 */
	URI getRedirectCallBackURI();

	String getRedirectCallBackAsStr();

}