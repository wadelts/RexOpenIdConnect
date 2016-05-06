package com.rest.example.service;

import java.net.URI;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.rexcanium.oidc.OpenIdConnClientInformation;
import com.rexcanium.oidc.OpenIdConnTokenSet;
import com.rexcanium.oidc.nimbus.OpenIdConnProviderConfigNimbus;



public interface OIDCService {
	URI generateAuthenticationRequestRedirectURI();
	String extractCodeFromRequestURL(String requestURL);
	OpenIdConnTokenSet retrieveTokenSetFromProvider(String authorizationCode);
	JSONObject retrieveUserClaimsFromProvider(JSONObject accessToken);
}
