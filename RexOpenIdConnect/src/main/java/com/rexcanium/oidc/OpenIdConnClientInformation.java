package com.rexcanium.oidc;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;

/**
 * Client data required for connecting to service provider.
 * 
 * @author wadel
 *
 */
public class OpenIdConnClientInformation {
	private ClientID clientID;
	private Secret clientSecret;

	public OpenIdConnClientInformation(ClientID clientID, Secret clientSecret) {
		this.clientID = clientID;
		this.clientSecret = clientSecret;
	}

	public ClientID getClientID() {
		return clientID;
	}

	public Secret getClientSecret() {
		return clientSecret;
	}
}