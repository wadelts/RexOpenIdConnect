package com.rexcanium.oidc;

import java.net.URI;

import net.minidev.json.JSONObject;

/**
 * Controls access to the OIDC Provider.
 * Allows us query the Provider to retrieve IdTokens, AccessTokens, RefreshTokens and additional User Information.
 * 
 * @author wadel
 *
 */
public interface OpenIdConnProvider {

	/**
	 * Create the URI we should return to the User, redirecting to the Provider's authentication endpoint.
	 * 
	 * @param authenticationRequestInfo information unique to this authentication request, will supply data to be included in the URL
	 * @return the URI to be used in the HTTP redirect response
	 */
	public abstract URI generateAuthenticationRequestRedirectURI(OpenIdConnAuthenticationRequest authenticationRequestInfo);

	/**
	 * Extract the Code returned in the supplied URL, iff the returned State value matches that retained for this Authentication request
	 * 
	 * @param requestURLFromProvider the URL of the request redirected from Provider - conatains the the new Code and returned State values
	 * @param authenticationRequestInfo the data cached by server to allow us confirm the request was one we expected
	 * 
	 * @exception OpenIdConnProviderException if cannot parse the supplied requestURLFromProvider OR if Provider returns an error OR the State value returned does not match that retained by server.
	 * 
	 * @return the Code, which we can now use to retrieve an IdToken from the Provider
	 */
	public abstract String extractCodeFromRequestURL(String requestURLFromProvider, OpenIdConnAuthenticationRequest authenticationRequestInfo);

	/**
	 * Use the supplied code to retrieve an IdToken (and AccessToken, to allow retrieval of further information about the User) from the Provider
	 * @param authorizationCode the Code supplied to us by the Provider that will allow the retrieval of an IdToken for the User
	 * 
	 * @exception OpenIdConnProviderException if could not query Provider OR cannot parse the response from Provider OR Provider returns an error.
	 * 
	 * @return the tokens returned by the Provider - an ID token, an access token and possibly a refresh token 
	 */
	public abstract OpenIdConnTokenSet retrieveTokenSetFromProvider(String authorizationCode);

	/**
	 * Given an access token supplied by the Provider, retrieve further information about the User (called claims in OIDC parlance)
	 * @param accessToken the token that will allow us access to additional User information, held by the Provider
	 * 
	 * @exception OpenIdConnProviderException if could not query Provider OR cannot parse the response from Provider OR Provider returns an error.
	 * 
	 * @return the set of Claims about the User
	 */
	public abstract JSONObject retrieveUserClaimsFromProvider(JSONObject accessToken);

}