package com.rexcanium.oidc;

import static org.junit.Assert.*;

import org.junit.Test;

import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

public class OpenIdConnAuthenticationRequestTest {

	@Test
	public void testCtrWithDefaultNonceAndState() {
		OpenIdConnAuthenticationRequest authenticationRequest = new OpenIdConnAuthenticationRequest("email");
		
		assertEquals("Expected two Scopes", 2, authenticationRequest.getScope().size());
		assertTrue("Expected email scope to be included", authenticationRequest.getScope().contains(OIDCScopeValue.EMAIL));
		assertTrue("Expected openid scope to be included", authenticationRequest.getScope().contains(OIDCScopeValue.OPENID));
	}

}
