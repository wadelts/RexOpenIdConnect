package com.rexcanium.oidc;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Arrays;

import net.minidev.json.JSONObject;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.rexcanium.oidc.nimbus.OpenIdConnProviderNimbus;
import com.rexcanium.oidc.nimbus.OpenIdConnTestBase;

public class OpenIdConnProviderTest extends OpenIdConnTestBase {
	
	@BeforeClass // remove this, only checking stuff out !!!!!
	public static void oneTimeSetUp() {
		ClassLoader.getSystemClassLoader().setDefaultAssertionStatus(true);
	}
	
	@Rule
	public ExpectedException thrown = ExpectedException.none();
	
	@Test
	public void testGenertatesCorrectAuthenticationRequestRedirectURI() throws IOException, URISyntaxException {
		String DUMMY_STATE_VALUE = "dummyStateValue";
		String DUMMY_NONCE_VALUE = "dummyNonceValue";
		// Given
		// These stubs simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);
		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);
		// Create config and provider instances
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();
	    OpenIdConnProvider provider = OpenIdConnProviderNimbus.fromConfiguration(providerConfig);
	    OpenIdConnAuthenticationRequest authenticationRequestInfo = new OpenIdConnAuthenticationRequest(DUMMY_STATE_VALUE, DUMMY_NONCE_VALUE, Arrays.asList("email"));		
	    // Construct the full expected redirect address 
		String CALLBACK_ADDRESS_URL_ENCODED = URLEncoder.encode(CALLBACK_ADDRESS, "UTF-8");
		String EXPECTED_REDIRECT_ADDRESS = providerConfig.getAuthorizationEndpointURI() + "?response_type=code&client_id=" + providerConfig.getClientID() + "&redirect_uri=" + CALLBACK_ADDRESS_URL_ENCODED + "&scope=openid+email&state=" + DUMMY_STATE_VALUE + "&nonce=" + DUMMY_NONCE_VALUE;

		// When
	    URI generatedRedirectURI = provider.generateAuthenticationRequestRedirectURI(authenticationRequestInfo);

	    // Then
	    assertEquals("Incorrect Authentication Request CallBack URI", EXPECTED_REDIRECT_ADDRESS, generatedRedirectURI.toString());
/*
	    verify(postRequestedFor(urlMatching("/my/resource/[a-z0-9]+"))
	            .withRequestBody(matching(".*<message>1234</message>.*"))
	            .withHeader("Content-Type", notMatching("application/json")));
*/
	}

	@Test
	public void testExtractCodeFromRequestURL() throws IOException, URISyntaxException {
		String DUMMY_STATE_VALUE = "dummyStateValue";
		String DUMMY_NONCE_VALUE = "dummyNonceValue";
		String EXPECTED_CODE = "4/4Rhemp3aPWwpWt8CMEKkxUMhOu5BctD5W11l6YkUJG0";
		// These stubs simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);
		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);
		// Create config, provider and authentication request instances
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();
	    OpenIdConnProvider provider = OpenIdConnProviderNimbus.fromConfiguration(providerConfig);
	    OpenIdConnAuthenticationRequest authenticationRequestInfo = new OpenIdConnAuthenticationRequest(DUMMY_STATE_VALUE, DUMMY_NONCE_VALUE, Arrays.asList("email"));		

		// Given
	    String requestURLFromProvider = "http://www.rexcanium.fr/test-OIDC-app/entry-point/OIDC-receive-auth-code?state=" + DUMMY_STATE_VALUE + "&code=" + EXPECTED_CODE + "&authuser=0&session_state=9be4c946ed4c645f46b41aa808680a3bfe994bf0..e899&prompt=consent#";

	    // When
	    String extractedCode = provider.extractCodeFromRequestURL(null, authenticationRequestInfo);

	    // Then
	    assertEquals("Incorrect Authentication Request CallBack URI", EXPECTED_CODE, extractedCode);
	}

	@Test
	public void testThrowExceptionWhenStateIncorrectForExtractCodeFromRequestURL() throws IOException, URISyntaxException {
		String DUMMY_STATE_VALUE = "dummyStateValue";
		String BAD_STATE_VALUE = "incorrectStateValue";
		String DUMMY_NONCE_VALUE = "dummyNonceValue";
		
		// These stubs simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);
		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);
		// Create config and provider instances
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();
	    OpenIdConnProvider provider = OpenIdConnProviderNimbus.fromConfiguration(providerConfig);
	    OpenIdConnAuthenticationRequest authenticationRequestInfo = new OpenIdConnAuthenticationRequest(DUMMY_STATE_VALUE, DUMMY_NONCE_VALUE, Arrays.asList("email"));		

	    thrown.expect(OpenIdConnProviderException.class);

	    // Given
	    String requestURLFromProvider = "http://www.rexcanium.fr/test-OIDC-app/entry-point/OIDC-receive-auth-code?state=" + BAD_STATE_VALUE + "&code=4/4Rhemp3aPWwpWt8CMEKkxUMhOu5BctD5W11l6YkUJG0&authuser=0&session_state=9be4c946ed4c645f46b41aa808680a3bfe994bf0..e899&prompt=consent#";

	    // When
	    String extractedCode = provider.extractCodeFromRequestURL(requestURLFromProvider, authenticationRequestInfo);

	    // Then
	    thrown.expectMessage("The State value was found to be different than expected in the return Request URL. Expected: dummyStateValue Found: incorrectStateValue");
	}

	@Test
	public void testWhenCodeSuppliedThenRetrieveCorrectIdTokenFromProvider() throws IOException, URISyntaxException {
		String AUTHORISATION_CODE_PARAM_NAME = "code";
		String AUTHORISATION_CODE = "someMadeUpCode";
		String AUTHORISATION_CODE_PARAM_STRING = AUTHORISATION_CODE_PARAM_NAME + "=" + AUTHORISATION_CODE;
		String EXPECTED_ID_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE0MTYzNjE5NDIzZGNkM2E3MzYxYWNmMmE2NDFiZjZmN2M5ZTQ4OGEifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdF9oYXNoIjoiTjJVd2NZNTJCc1JkWGp4eS1hczVhQSIsImF1ZCI6IjEzNjE4ODgwOTU2Mi1uajMzZXQxZWZzaHM1bzY0M3MxaThkZGNjYmw5cGYyai5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwMzM1NzAyOTEyMTM5NTk0ODk0MSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhenAiOiIxMzYxODg4MDk1NjItbmozM2V0MWVmc2hzNW82NDNzMWk4ZGRjY2JsOXBmMmouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJub25jZSI6ImFCYlpzaUNwX0EyaERMMy1iQVFRQjdvOTdSU1dIYkFOY2FyYXZfUURYX0kiLCJlbWFpbCI6ImxpYW0ud2FkZS50czJAZ21haWwuY29tIiwiaWF0IjoxNDU1Mjg0ODM2LCJleHAiOjE0NTUyODg0MzZ9.B7OL3z_nvuu4Qv7L7xrruhBsvsVPo4QxThBQhDW0nm4nFolN5AXxfwGuuNdzAXYK5mjJIBQ0A_NQgWSJBsQ9-JneokkBAY85TI6mUMvOV_9MH78xWPWVvgl4ZaCVpTLYVTxXheqUNtAMmmsva9jNkVVxs_L9J3iCrlsIK7TsyPITyH3axRWyjpwqcwwmN-dgX9bj_o7cOXI1KjLm5rqIlEw4jDvkjfqVy0RqGBEU0oQjEukw1yFSOv7z4QINfpPQ6aswbXly1EZmpL-IFqBZ08RWAqv_I5-dkr14qwPFYY7FgZ2jG5e7mZzLr2DeOdkqaUhVhVbNA3xfiavV4OdxLA";

		// These stubs simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);
		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);
		// Create config, provider and authentication request instances
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();
	    OpenIdConnProvider provider = OpenIdConnProviderNimbus.fromConfiguration(providerConfig);

		// Given
	    stubPostWithBodyContainingAtEndpointFor200JSONFromFile(providerConfig.getTokenEndpointURI().getPath(),
				  										 JSONMockResponseToTokenSetRequest_PATH, 
				  										 AUTHORISATION_CODE_PARAM_STRING); // If string not in body, WireMock stub will return 404 Not Found
	    // When
	    OpenIdConnTokenSet tokenSet = provider.retrieveTokenSetFromProvider(AUTHORISATION_CODE);

	    // Then
	    assertEquals("Incorrect ID Token returned from Provider", EXPECTED_ID_TOKEN, tokenSet.getIDToken().getParsedString());
	}

	@Test
	public void testWhenAccessTokenSuppliedThenRetrieveCorrectClaimsFromProvider() throws IOException, URISyntaxException {
		String AUTHORISATION_CODE_PARAM_NAME = "code";
		String AUTHORISATION_CODE = "someMadeUpCode";
		String AUTHORISATION_CODE_PARAM_STRING = AUTHORISATION_CODE_PARAM_NAME + "=" + AUTHORISATION_CODE;
		String EXPECTED_CLAIMS_SUB = "103357029121395948941";
		String EXPECTED_CLAIMS_EMAIL = "liam.wade.ts2@gmail.com";
		
		// These stubs simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);
		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);
		// Create config, provider and authentication request instances
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();
	    OpenIdConnProvider provider = OpenIdConnProviderNimbus.fromConfiguration(providerConfig);

		// Given
	    stubPostWithBodyContainingAtEndpointFor200JSONFromFile(providerConfig.getTokenEndpointURI().getPath(),
				  										 		JSONMockResponseToTokenSetRequest_PATH, 
				  										 		AUTHORISATION_CODE_PARAM_STRING); // If string not in body, WireMock stub will return 404 Not Found
	    
	    OpenIdConnTokenSet tokenSet = provider.retrieveTokenSetFromProvider(AUTHORISATION_CODE);
	    stubGetAtEndpointFor200JSONFromFile(providerConfig.getUserInfoEndpointURI().getPath(),
	    									JSONMockResponseToUserClaimsRequest_PATH);
	    
	    // When
	    JSONObject userclaims = provider.retrieveUserClaimsFromProvider(tokenSet.getAccessToken().toJSONObject());
	    
	    // Then
	    assertEquals("Incorrect Claims Subject returned from Provider", EXPECTED_CLAIMS_SUB, userclaims.get("sub"));
	    assertEquals("Incorrect Claims email returned from Provider", EXPECTED_CLAIMS_EMAIL, userclaims.get("email"));
	}

}
