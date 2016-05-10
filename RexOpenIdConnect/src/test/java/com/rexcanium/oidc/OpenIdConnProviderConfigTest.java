package com.rexcanium.oidc;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.containsString;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;





import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;





import com.nimbusds.jose.util.Base64URL;
import com.rexcanium.oidc.nimbus.OpenIdConnProviderConfigNimbus;
import com.rexcanium.oidc.nimbus.OpenIdConnTestBase;


public class OpenIdConnProviderConfigTest extends OpenIdConnTestBase {
	 
	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testMetaDataLoadedWhenInitialised() throws IOException, URISyntaxException {
		// Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);

		// This is the relevant stub
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	    assertEquals("Incorrect CallBackStr", CALLBACK_ADDRESS, providerConfig.getRedirectCallBackAsStr());
/*
	    verify(postRequestedFor(urlMatching("/my/resource/[a-z0-9]+"))
	            .withRequestBody(matching(".*<message>1234</message>.*"))
	            .withHeader("Content-Type", notMatching("application/json")));
*/
	}

	@Test
	public void testMetaDataNotLoadedWhenInitialisedWithInvalidProviderDomainURI() throws IOException, URISyntaxException {
		String INVALID_DOMAIN_URL = "http://local\"host";
		
	    thrown.expect(OpenIdConnProviderConfigException.class);
	    // ensure Exception not from other cause...
	    thrown.expectMessage(containsString("Error trying to create Provider configuration URI from ")); 

	    // When
		OpenIdConnProviderConfig providerConfig = OpenIdConnProviderConfigNimbus.fromEndPoint(
															INVALID_DOMAIN_URL,
															PROVIDER_CONFIG_ENDPOINT,
															CLIENT_INFO,
															CALLBACK_ADDRESS);	
	}

	@Test
	public void testMetaDataNotLoadedWhenInitialisedWithInvalidProviderURL() throws IOException, URISyntaxException {
		String INVALID_ENDPOINT = "/bad/end\"point";
		
	    thrown.expect(OpenIdConnProviderConfigException.class);
	    // ensure Exception not from other cause...
	    thrown.expectMessage(containsString("Error trying to create Provider configuration URI from ")); 

	    // When
		OpenIdConnProviderConfig providerConfig = OpenIdConnProviderConfigNimbus.fromEndPoint(
															PROVIDER_DOMAIN_AND_PORT,
															INVALID_ENDPOINT,
															CLIENT_INFO,
															CALLBACK_ADDRESS);	
	}

	@Test
	public void testMetaDataNotLoadedWhenInitialisedWithInvalidEndpoint() throws IOException, URISyntaxException {
		// Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);

		// Don't stub, so Endpoint invalid

	    thrown.expect(OpenIdConnProviderConfigException.class);
	    thrown.expectMessage("Error trying open stream on Provider URL"); // ensure Exception not from other cause

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	}

	@Test
	public void testMetaDataNotLoadedWhenInitialisedWithBadJSON() throws IOException, URISyntaxException {
		// Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);

		// This is the relevant stub
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequestBadJSON_PATH);

	    thrown.expect(OpenIdConnProviderConfigException.class);
	    // ensure Exception not from other cause...
	    thrown.expectMessage("Error trying to parse config data returned by Provider"); 

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	}

	@Test
	public void testKeySetLoadedWhenInitialised() throws IOException, URISyntaxException {
		// These values are those in file JSONMockResponseToConfigRequest_PATH,
		// which will be delivered via HTTP to providerConfig...
		String EXPECTED_KEY_ID = "a4163619423dcd3a7361acf2a641bf6f7c9e488a";
		Base64URL EXPECTED_MODULUS = new Base64URL("vOVVY2TB36Suju1PiOn6i3BXaAppG8vDhI-rjHOY0DYOOOu34OweP0w0noOQ2DsDOoCjKi8ElkKqAzlNTOZcmOvQzGvYZ50KdDSIjhhcy_Vr_gkKZVhCFrgmW47DarJVyAbqgwH9Usn1jbctU9kXiT1ds8AFd6LS_wKTTQCgOv-ZQwqsSsYwcKoKYIC5T8nmCHTg0wEVkAKsdOr9NG8UKt1xhSpb_ouC-spjt23hmgo0B_1vSr-OvS-hZXyezFPBX_I4xtT8eYuezT0sunvelgjIG7mJMwTXGvWGLRWL0lW3yLieHLtuxU-r2-w1ljcMyDoorTN2EKJ1GjrejE0U1w"); // "n" value
		BigInteger EXPECTED_MODULUS_AS_NUMBER = EXPECTED_MODULUS.decodeToBigInteger(); 
		BigInteger EXPECTED_PUBLIC_EXPONENT_AS_NUMBER = new Base64URL("AQAB").decodeToBigInteger(); // "e" value

	    // Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);

		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequest_PATH);

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	    assertEquals("Incorrect Provider Key", EXPECTED_MODULUS_AS_NUMBER, 
	    									   providerConfig.getProviderKey(EXPECTED_KEY_ID).getModulus());
	    assertEquals("Incorrect Provider Key", EXPECTED_PUBLIC_EXPONENT_AS_NUMBER, 
	    									   providerConfig.getProviderKey(EXPECTED_KEY_ID).getPublicExponent());
	}

	@Test
	public void testKeySetNotLoadedWhenInitialisedWithNoKid() throws IOException, URISyntaxException {
		// These values are those in file JSONMockResponseToConfigRequest_PATH, which will be delivered via HTTP to providerConfig...
		String EXPECTED_KEY_ID = ""; // Note must be empty string, as no Kid supplied
		Base64URL EXPECTED_MODULUS = new Base64URL("vOVVY2TB36Suju1PiOn6i3BXaAppG8vDhI-rjHOY0DYOOOu34OweP0w0noOQ2DsDOoCjKi8ElkKqAzlNTOZcmOvQzGvYZ50KdDSIjhhcy_Vr_gkKZVhCFrgmW47DarJVyAbqgwH9Usn1jbctU9kXiT1ds8AFd6LS_wKTTQCgOv-ZQwqsSsYwcKoKYIC5T8nmCHTg0wEVkAKsdOr9NG8UKt1xhSpb_ouC-spjt23hmgo0B_1vSr-OvS-hZXyezFPBX_I4xtT8eYuezT0sunvelgjIG7mJMwTXGvWGLRWL0lW3yLieHLtuxU-r2-w1ljcMyDoorTN2EKJ1GjrejE0U1w"); // "n" value
		BigInteger EXPECTED_MODULUS_AS_NUMBER = EXPECTED_MODULUS.decodeToBigInteger(); 
		BigInteger EXPECTED_PUBLIC_EXPONENT_AS_NUMBER = new Base64URL("AQAB").decodeToBigInteger(); // "e" value

	    // Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);

		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequestNoKid_PATH);

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	    assertEquals("Incorrect Provider Key", EXPECTED_MODULUS_AS_NUMBER, 
	    									   providerConfig.getProviderKey(EXPECTED_KEY_ID).getModulus());
	    assertEquals("Incorrect Provider Key", EXPECTED_PUBLIC_EXPONENT_AS_NUMBER, 
	    									   providerConfig.getProviderKey(EXPECTED_KEY_ID).getPublicExponent());
	}

	@Test
	public void testKeySetNotLoadedWhenInitialisedWithInvalidKeysEndpoint() throws IOException, URISyntaxException {
		// These values are those in file JSONMockResponseToConfigRequest_PATH,
		// which will be delivered via HTTP to providerConfig...
		Base64URL EXPECTED_MODULUS = new Base64URL("vOVVY2TB36Suju1PiOn6i3BXaAppG8vDhI-rjHOY0DYOOOu34OweP0w0noOQ2DsDOoCjKi8ElkKqAzlNTOZcmOvQzGvYZ50KdDSIjhhcy_Vr_gkKZVhCFrgmW47DarJVyAbqgwH9Usn1jbctU9kXiT1ds8AFd6LS_wKTTQCgOv-ZQwqsSsYwcKoKYIC5T8nmCHTg0wEVkAKsdOr9NG8UKt1xhSpb_ouC-spjt23hmgo0B_1vSr-OvS-hZXyezFPBX_I4xtT8eYuezT0sunvelgjIG7mJMwTXGvWGLRWL0lW3yLieHLtuxU-r2-w1ljcMyDoorTN2EKJ1GjrejE0U1w"); // "n" value

	    // Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);

		// Note, no KEYSET_ENDPOINT stub requested
	    thrown.expect(OpenIdConnProviderConfigException.class);
	    // ensure Exception not from other cause...
	    thrown.expectMessage("Error trying to open stream to retrieve RSA Key from Provider"); 

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	}

	@Test
	public void testKeySetNotLoadedWhenInitialisedWithBadJSON() throws IOException, URISyntaxException {

	    // Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);

		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequestBadJSON_PATH);

	    thrown.expect(OpenIdConnProviderConfigException.class);
	    // ensure Exception not from other cause...
	    thrown.expectMessage("Error trying to parse RSA Key from Provider as Jason data");

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	}
	
	@Test
	public void testKeySetNotLoadedWhenInitialisedWithBadRSAKey() throws IOException, URISyntaxException {

	    // Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);

		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONMockResponseToKeySetRequestBadRSAKey_PATH);

	    thrown.expect(OpenIdConnProviderConfigException.class);
	    // ensure Exception not from other cause...
	    thrown.expectMessage("Error trying to parse RSA Key returned by Provider");

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	}

	@Test
	public void testKeySetNotLoadedWhenInitialisedWithNoKeys() throws IOException, URISyntaxException {

	    // Given
		// This stub simply to allow OpenIdConnProviderConfigNimbus proceed
		stubGetAtEndpointFor200JSONFromFile(PROVIDER_CONFIG_ENDPOINT, JSONMockResponseToConfigRequest_PATH);

		stubGetAtEndpointFor200JSONFromFile(KEYSET_ENDPOINT, JSONResponseToKeySetRequestMockNoKeys_PATH);

	    thrown.expect(NullPointerException.class);
	    // ensure Exception not from other cause...
	    thrown.expectMessage("Value for keys list in JSON");

	    // When
		OpenIdConnProviderConfig providerConfig = createConfigFixture().initialise();

	    // Then
	}
}
