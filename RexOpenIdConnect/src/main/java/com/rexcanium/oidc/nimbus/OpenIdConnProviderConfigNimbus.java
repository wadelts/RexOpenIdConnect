package com.rexcanium.oidc.nimbus;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.rexcanium.oidc.OpenIdConnClientInformation;
import com.rexcanium.oidc.OpenIdConnProviderConfig;
import com.rexcanium.oidc.OpenIdConnProviderConfigException;

public class OpenIdConnProviderConfigNimbus implements OpenIdConnProviderConfig {
	private static final Logger logger = LoggerFactory.getLogger(OpenIdConnProviderConfigNimbus.class);

    private URL providerConfigurationURL;
	private OIDCProviderMetadata providerMetadata;
	private Map<String, RSAPublicKey> providerKeySet = new HashMap<>();
	private OpenIdConnClientInformation clientInformation;
	private URI redirectCallBackURI;

	
	private OpenIdConnProviderConfigNimbus(String providerConfigAddress, String providerConfigEndpoint, 
											OpenIdConnClientInformation clientInformation, String redirectCallBackAddress) {
		
		try {
			URI providerConfigURI = new URI(providerConfigAddress);
			this.providerConfigurationURL = providerConfigURI.resolve(providerConfigEndpoint).toURL();
		} catch (IllegalArgumentException | URISyntaxException e) {
			logger.error("constructor: Error trying to create Provider configuration URI from " + providerConfigAddress +
						providerConfigEndpoint + ": ", e);
			throw new OpenIdConnProviderConfigException("constructor: Error trying to create Provider" +
									" configuration URI from " + providerConfigAddress + providerConfigEndpoint + ": ", e);
		} catch (MalformedURLException e) {
			logger.error("constructor: Error trying to create Provider configuration URL from " + providerConfigEndpoint +
						": ", e);
			throw new OpenIdConnProviderConfigException("constructor: Error trying to create Provider" +
									" configuration URL from " + providerConfigAddress + providerConfigEndpoint + ": ", e);
		}
		
		this.clientInformation = clientInformation;

		try {
			this.redirectCallBackURI = new URI(redirectCallBackAddress);
		} catch (IllegalArgumentException | URISyntaxException e) {
			logger.error("constructor: URISyntaxException creating URI from redirectCallBackAddress!" + e.getMessage());
			throw new OpenIdConnProviderConfigException("constructor: URISyntaxException creating URI from" +
														" redirectCallBackAddress!" + e.getMessage());
		}
	}
	
	/**
	 * Create an OpenIdConnProviderConfigNimbus object from the data supplied.
	 * You MUST call initialise() to tell this object to retrieve the configuration data from the Provider.
	 * 
	 * @param providerConfigAddress	the domain name of the OIDC Provider
	 * @param providerConfigEndpoint the endpoint at the providerConfigAddress from where configuration data may be retrieved
	 * @param clientInformation the client ID and secret required to communicate with the Provider
	 * @param redirectCallBackAddress the address to which the Provider should redirect the user (e.g. via Browser) when supplying the Code
	 */
	public static OpenIdConnProviderConfig fromEndPoint(String providerConfigAddress,
														String providerConfigEndpoint, 
														OpenIdConnClientInformation clientInformation,
														String redirectCallBackAddress) {
		return new OpenIdConnProviderConfigNimbus(providerConfigAddress, providerConfigEndpoint,
												  clientInformation, redirectCallBackAddress);
	}

	@Override
	public OpenIdConnProviderConfig initialise() {
		populateMetaDataAndThen()
			.populateProviderKeySet(); // has temporal dependency on populateMetaData
		return this;
	}

	private OpenIdConnProviderConfigNimbus populateMetaDataAndThen() {
		try {
			providerMetadata = getProviderMetadataFromProvider();
		} catch (IOException e) {
			logger.error("populateMetaDataAndThen: Error trying open stream on Provider URL", e);
			throw new OpenIdConnProviderConfigException("populateMetaDataAndThen: Error trying open" +
														" stream on Provider URL", e);
		} catch (ParseException e) {
			logger.error("populateMetaDataAndThen: Error trying to parse config data returned by Provider", e);
			throw new OpenIdConnProviderConfigException("populateMetaDataAndThen: Error trying to" +
														" parse config data returned by Provider", e);
		}
		
		return this;
	}
	
	private OIDCProviderMetadata getProviderMetadataFromProvider() throws IOException, ParseException {
		//Scanner will tokenize entire stream, from beginning to "next beginning"...
		String REGEX_START_OF_TEXT_MATCHER = "\\A";
		
		InputStream stream = providerConfigurationURL.openStream();

		// Read all data from URL
		String providerInfo = null;
		try (java.util.Scanner s = new java.util.Scanner(stream)) {
		  providerInfo = s.useDelimiter(REGEX_START_OF_TEXT_MATCHER).hasNext() ? s.next() : "";
		}
		
		logger.info("getProviderMetadataFromProvider: len= " + providerInfo.length() + " providerInfo=" + providerInfo);

		return OIDCProviderMetadata.parse(providerInfo);

	}

	private void populateProviderKeySet() {
	    Map<String, JSONObject> keys = getProviderRSAKeys();
	    
	    keys.entrySet().forEach(this::parseAndSaveKey);
	    
	    if (keys.isEmpty()) {
	    	logger.error("populateProviderKeySet: No RSA Keys supplied by Provider");
			throw new OpenIdConnProviderConfigException("populateProviderKeySet: No RSA Keys supplied by Provider");
	    }
	}
	
	private Map<String, JSONObject> getProviderRSAKeys() {

		InputStream is = openConnectionToProviderKeysEndPoint();
		String jsonString = readAllDataFromStream(is);

		logger.debug("getProviderRSAKeys: len= " + jsonString.length() + " providerInfo=" + jsonString);

		JSONObject json = buildJSONObjectFrom(jsonString);

		return extractKeysFrom(json);
	}

	private InputStream openConnectionToProviderKeysEndPoint() {
		try {
			return providerMetadata.getJWKSetURI().toURL().openStream();
		} catch (IOException e) {
			logger.error("openConnectionToProviderKeysEndPoint: Error trying to open stream to retrieve" +
						 " RSA Key from Provider", e);
			throw new OpenIdConnProviderConfigException("openConnectionToProviderKeysEndPoint: Error trying" +
						 								" to open stream to retrieve RSA Key from Provider", e);
		}
	}

	private String readAllDataFromStream(InputStream is) {
		assert is != null; 
		// Read all data from stream
		StringBuilder sb = new StringBuilder();
		try (Scanner scanner = new Scanner(is)) {
		    while (scanner.hasNext()) {
		      sb.append(scanner.next());
		    }
		}
		String data = sb.toString();
		return data;
	}

	private JSONObject buildJSONObjectFrom(String jsonString) {
		assert jsonString != null; 
		try {
			return JSONObjectUtils.parseJSONObject(jsonString);
		} catch (java.text.ParseException e) {
			logger.error("buildJSONObjectFrom: Error trying to parse RSA Key from Provider as Jason data", e);
			throw new OpenIdConnProviderConfigException("buildJSONObjectFrom: Error trying to parse" +
														" RSA Key from Provider as Jason data", e);
		}
	}

	/*
	 * Find the RSA signing key - I'm assuming here that, if I find
	 * a key without a kid (key ID), there should be only one, so,
	 * if there IS more than one, the last one will be the one saved
	 * (with key = "").
 
	 */
	private Map<String, JSONObject> extractKeysFrom(JSONObject json) {
		assert json != null;
		checkNotNull(json.get("keys"), "keys list in JSON supplied to extractKeysFrom()");
		
		JSONArray keyList = (JSONArray) json.get("keys");
		
		Map<String, JSONObject> foundKeys = keyList
			.stream()
			.map(key -> (JSONObject) key)
			.filter(isRelevantKeyEntry)
			.collect(
				Collectors.toMap(childAsAStringNamed("kid"), k -> k)
			 );
			
		foundKeys.forEach((kid, value) -> {
			String kidMessage = (("".equals(kid)) ? "kid Not supplied" : "with kid=" + kid);
			logger.debug(String.format("extractKeysFrom: Retained sig/RSA key from Provider (%s): Value=%s", kidMessage, value.toString()));
		});

		return foundKeys;
	}
	
	private Predicate<JSONObject> isRelevantKeyEntry = key -> key.get("use").equals("sig") && key.get("kty").equals("RSA") ;
	
	private Function<JSONObject, String> childAsAStringNamed(String childName) {
		return jsonObjectParent -> {return (jsonObjectParent.get(childName) == null) ? "" : (String) jsonObjectParent.get(childName);};
	}

	private void parseAndSaveKey(Entry<String, JSONObject> nextKey) {
		try {
			providerKeySet.put(nextKey.getKey(), RSAKey.parse(nextKey.getValue()).toRSAPublicKey());
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | java.text.ParseException e) {
			logger.error("populateProviderKeySet: Error trying to parse RSA Key returned by Provider", e);
			throw new OpenIdConnProviderConfigException("populateProviderKeySet: Error trying to parse" +
														" RSA Key returned by Provider", e);
		}
	}

	@Override
	public URI getAuthorizationEndpointURI() {
		return getProviderMetadata().getAuthorizationEndpointURI();
	}
	
	@Override
	public URI getTokenEndpointURI() {
		return getProviderMetadata().getTokenEndpointURI();
	}
	
	@Override
	public URI getUserInfoEndpointURI() {
		return getProviderMetadata().getUserInfoEndpointURI();
	}
	
	@Override
	public String getClientID() {
		return getClientInformation().getClientID().toString();
	}
	
	@Override
	public String getClientSecret() {
		return getClientInformation().getClientSecret().getValue();
	}
	
	@Override
	public RSAPublicKey getProviderKey(String kid) {
		checkNotNull(kid, "kid supplied to getProviderKey()");
		return providerKeySet.get(kid);
	}

	@Override
	public URI getRedirectCallBackURI() {
		return redirectCallBackURI;
	}

	@Override
	public String getRedirectCallBackAsStr() {
		return redirectCallBackURI.toASCIIString();
	}

	private OIDCProviderMetadata getProviderMetadata() {
		return providerMetadata;
	}

	private OpenIdConnClientInformation getClientInformation() {
		return clientInformation;
	}

	private void checkNotNull(Object o, String name) {
		if (o == null) {
			String msg = String.format("checkNotNull: Value for %s found to be null!", name);
			logger.error(msg);
			throw new NullPointerException("OpenIdConnProviderConfigNimbus." + msg);
		}
	}
}
