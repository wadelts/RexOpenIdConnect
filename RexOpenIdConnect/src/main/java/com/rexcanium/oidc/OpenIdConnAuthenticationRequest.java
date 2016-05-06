package com.rexcanium.oidc;

import java.util.List;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

/**
 * Gathers together the data required when making an
 * Authentication request. 
 * 
 * @author wadel
 *
 */
public class OpenIdConnAuthenticationRequest {

	private final static String OPEN_ID_SCOPE = "openid";
	
	// Generate random state string for pairing the response to the request
	private State state = new State();
	private Nonce nonce = new Nonce();
	private Scope scope = new Scope();


	/**
	 * Allows us create a request while supplying our own State value
	 * 
	 * @param scopes scopes to be included in the request, in addition to "openid" (which is automatically included)
	 */
	public OpenIdConnAuthenticationRequest(String... scopes) {
		this.scope.add(OIDCScopeValue.OPENID);
		for (String scope : scopes) {
			if ( ! OPEN_ID_SCOPE.equals(scope) ) {
				this.scope.add(scope);
			}
		}
	}

	/**
	 * Allows us create a request while supplying our own State and Nonce values
	 * 
	 * @param state the State to retain for later validation, to be used instead of an automatically-generated one.
	 * @param nonce the Nonce to send to the Provider, to be used instead of an automatically-generated one.
	 * @param scopes scopes to be included in the request, in addition to "openid" (which is automatically included)
	 */
	public OpenIdConnAuthenticationRequest(String state, String nonce, List<String> scopes) {
		this.state = new State(state);
		this.nonce = new Nonce(nonce);
		this.scope.add(OIDCScopeValue.OPENID);
		for (String scope : scopes) {
			if ( ! OPEN_ID_SCOPE.equals(scope) ) {
				this.scope.add(scope);
			}
		}
	}


	public State getState() {
		return state;
	}


	public Nonce getNonce() {
		return nonce;
	}


	public Scope getScope() {
		return scope;
	}

}
