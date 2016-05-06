package com.rest.example.service;

import java.net.URI;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.rexcanium.oidc.OpenIdConnAuthenticationRequest;
import com.rexcanium.oidc.OpenIdConnProvider;
import com.rexcanium.oidc.OpenIdConnClientInformation;
import com.rexcanium.oidc.OpenIdConnProviderConfig;
import com.rexcanium.oidc.OpenIdConnTokenSet;
import com.rexcanium.oidc.nimbus.OpenIdConnProviderConfigNimbus;
import com.rexcanium.oidc.nimbus.OpenIdConnProviderNimbus;

public class OIDCServiceImpl implements OIDCService {

	// Need to create this on receipt of logon request and store in session (or Db if want to scale) until Provider comes back with Code
	private static OpenIdConnAuthenticationRequest authenticationRequest = new OpenIdConnAuthenticationRequest("email");

//	private String CALLBACK_ADDRESS = "http://localhost:8282/entry-point/OIDC-receive-auth-code";
	private String CALLBACK_ADDRESS = "http://www.rexcanium.fr/test-OIDC-app/entry-point/OIDC-receive-auth-code";

	private  OpenIdConnClientInformation clientInformationForGoogle;

	// Note: Google wanted me to give the Redirect URI on the Credentials screen of my project (Jadoub) in Cloud Console, even though specification says we send with Auth redirect.
	private  OpenIdConnProviderConfig providerConfig;
	
	private OpenIdConnProvider provider;
	

	public OIDCServiceImpl() {
		super();

		this.clientInformationForGoogle = new OpenIdConnClientInformation(
				new ClientID("136188809562-nj33et1efshs5o643s1i8ddccbl9pf2j.apps.googleusercontent.com"),
				new Secret("Uf7af_GawLN6hCpv2pX0J4wk")
		);

		// Note: Google wanted me to give the Redirect URI on the Credentials screen of my project (Jadoub) in Cloud Console, even though specification says we send with Auth redirect.
		this.providerConfig = OpenIdConnProviderConfigNimbus.fromEndPoint(
																	"https://accounts.google.com/",
																	"/.well-known/openid-configuration",
																	clientInformationForGoogle,
																	CALLBACK_ADDRESS)
							  .initialise();
		this.provider = OpenIdConnProviderNimbus.fromConfiguration(providerConfig);
	}


	@Override
	public URI generateAuthenticationRequestRedirectURI() {
		return provider.generateAuthenticationRequestRedirectURI(authenticationRequest);
	}

	@Override
	public String extractCodeFromRequestURL(String requestURL) {
		return provider.extractCodeFromRequestURL(requestURL, authenticationRequest);
	}

	@Override
	public OpenIdConnTokenSet retrieveTokenSetFromProvider(String authorizationCode) {
		return provider.retrieveTokenSetFromProvider(authorizationCode);
	}

	@Override
	public JSONObject retrieveUserClaimsFromProvider(JSONObject accessToken) {
		return provider.retrieveUserClaimsFromProvider(accessToken);
	}

}
