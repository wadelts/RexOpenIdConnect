package com.rexcanium.oidc;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

public class OpenIdConnTokenSet {
	private JWT IDToken;
	private AccessToken accessToken;
	private RefreshToken refreshToken;
	
	public OpenIdConnTokenSet(JWT IDToken, AccessToken accessToken, RefreshToken refreshToken) {
		super();
		this.IDToken = IDToken;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}

	public JWT getIDToken() {
		return IDToken;
	}

	public AccessToken getAccessToken() {
		return accessToken;
	}

	public RefreshToken getRefreshToken() {
		return refreshToken;
	}
	
	
}
