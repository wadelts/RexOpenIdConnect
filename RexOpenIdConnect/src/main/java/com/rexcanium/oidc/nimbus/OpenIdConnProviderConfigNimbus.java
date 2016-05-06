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

	
	private OpenIdConnProviderConfigNimbus(String providerConfigAddress, String providerConfigEndpoint, OpenIdConnClientInformation clientInformation, String redirectCallBackAddress) {
		
		try {
			URI providerConfigURI = new URI(providerConfigAddress);
			this.providerConfigurationURL = providerConfigURI.resolve(providerConfigEndpoint).toURL();
		} catch (IllegalArgumentException | URISyntaxException e) {
			logger.error("constructor: Error trying to create Provider configuration URI from " + providerConfigAddress + providerConfigEndpoint + ": ", e);
			throw new OpenIdConnProviderConfigException("constructor: Error trying to create Provider configuration URI from " + providerConfigAddress + providerConfigEndpoint + ": ", e);
		} catch (MalformedURLException e) {
			logger.error("constructor: Error trying to create Provider configuration URL from " + providerConfigEndpoint + ": ", e);
			throw new OpenIdConnProviderConfigException("constructor: Error trying to create Provider configuration URL from " + providerConfigAddress + providerConfigEndpoint + ": ", e);
		}
		
		this.clientInformation = clientInformation;

		try {
			this.redirectCallBackURI = new URI(redirectCallBackAddress);
		} catch (IllegalArgumentException | URISyntaxException e) {
			logger.error("constructor: URISyntaxException creating URI from redirectCallBackAddress!" + e.getMessage());
			throw new OpenIdConnProviderConfigException("constructor: URISyntaxException creating URI from redirectCallBackAddress!" + e.getMessage());
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
	public static OpenIdConnProviderConfig fromEndPoint(String providerConfigAddress, String providerConfigEndpoint, OpenIdConnClientInformation clientInformation, String redirectCallBackAddress) {
		return new OpenIdConnProviderConfigNimbus(providerConfigAddress, providerConfigEndpoint, clientInformation, redirectCallBackAddress);
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
			throw new OpenIdConnProviderConfigException("populateMetaDataAndThen: Error trying open stream on Provider URL", e);
		} catch (ParseException e) {
			logger.error("populateMetaDataAndThen: Error trying to parse config data returned by Provider", e);
			throw new OpenIdConnProviderConfigException("populateMetaDataAndThen: Error trying to parse config data returned by Provider", e);
		}
		
		return this;
	}
	
	private OIDCProviderMetadata getProviderMetadataFromProvider() throws IOException, ParseException {
		InputStream stream = providerConfigurationURL.openStream();

		// Read all data from URL
		String providerInfo = null;
		try (java.util.Scanner s = new java.util.Scanner(stream)) {
		  providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
		}
		
		logger.info("providerMetadataFromProvider: len= " + providerInfo.length() + " providerInfo=" + providerInfo);

		return OIDCProviderMetadata.parse(providerInfo);

	}

	private void populateProviderKeySet() {
		try {
		    Map<String, JSONObject> keys = getProviderRSAKeys();
		    for (Entry<String, JSONObject> nextKey : keys.entrySet()) {
		    	providerKeySet.put(nextKey.getKey(), RSAKey.parse(nextKey.getValue()).toRSAPublicKey());
		    }
		} catch (NoSuchAlgorithmException | InvalidKeySpecException
		  | java.text.ParseException e) {
			logger.error("populateProviderKeySet: Error trying to parse RSA Key returned by Provider", e);
			throw new OpenIdConnProviderConfigException("populateProviderKeySet: Error trying to parse RSA Key returned by Provider", e);
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
			logger.error("openConnectionToProviderKeysEndPoint: Error trying to open stream to retrieve RSA Key from Provider", e);
			throw new OpenIdConnProviderConfigException("openConnectionToProviderKeysEndPoint: Error trying to open stream to retrieve RSA Key from Provider", e);
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
			throw new OpenIdConnProviderConfigException("buildJSONObjectFrom: Error trying to parse RSA Key from Provider as Jason data", e);
		}
	}

	private Map<String, JSONObject> extractKeysFrom(JSONObject json) {
		assert json != null;
		// Find the RSA signing key - I'm assuming here that, if I find a key without a kid, there IS only one, so return immediately.
		Map<String, JSONObject> foundKeys = new HashMap<>();
		JSONArray keyList = (JSONArray) json.get("keys");
		for (Object key : keyList) {
		    JSONObject k = (JSONObject) key;
		    if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
			    Object kid = k.get("kid");
			    if (kid == null) {
			    	foundKeys.put("", k);
					logger.debug("extractKeysFrom: Retained first-found sig/RSA key from Provider (as no kid was specified): Value=" + k.toString());
			    	return foundKeys;
			    } else {
			    	foundKeys.put( (String)kid, k );
					logger.debug("extractKeysFrom: Retained sig/RSA key from Provider (with kid=" + kid + "): Value=" + k.toString());
			    }
		    }
		}
		
		return foundKeys;
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
		if (kid == null) throw new NullPointerException("getProviderKey cannot accept null kid");
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

}
