package com.rexcanium.oidc.nimbus;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.rexcanium.oidc.OpenIdConnClientInformation;
import com.rexcanium.oidc.OpenIdConnProviderConfig;
import com.rexcanium.oidc.nimbus.OpenIdConnProviderConfigNimbus;

public class OpenIdConnTestBase {

	protected int PROVIDER_PORT = 8383;
	protected String PROVIDER_DOMAIN_AND_PORT = String.format("http://localhost:%d/", PROVIDER_PORT);
	protected String PROVIDER_CONFIG_ENDPOINT = "/.well-known/openid-configuration";
	protected String KEYSET_ENDPOINT = "/certs";

	protected String JSONMockResponseToConfigRequest_PATH = "C:/Users/wadel/eclipseWorkspaces/workspaceC-Spring/FirstGradle/src/test/resources/JSONResponseToConfigRequestMock.json";
	protected String JSONMockResponseToConfigRequestBadJSON_PATH = "C:/Users/wadel/eclipseWorkspaces/workspaceC-Spring/FirstGradle/src/test/resources/JSONResponseToConfigRequestMockBadJSON.json";
	protected String JSONMockResponseToKeySetRequest_PATH = "C:/Users/wadel/eclipseWorkspaces/workspaceC-Spring/FirstGradle/src/test/resources/JSONResponseToKeySetRequestMock.json";
	protected String JSONMockResponseToKeySetRequestNoKid_PATH = "C:/Users/wadel/eclipseWorkspaces/workspaceC-Spring/FirstGradle/src/test/resources/JSONResponseToKeySetRequestMockNoKid.json";
	protected String JSONMockResponseToKeySetRequestBadJSON_PATH = "C:/Users/wadel/eclipseWorkspaces/workspaceC-Spring/FirstGradle/src/test/resources/JSONResponseToKeySetRequestMockBadJSON.json";
	protected String JSONMockResponseToKeySetRequestBadRSAKey_PATH = "C:/Users/wadel/eclipseWorkspaces/workspaceC-Spring/FirstGradle/src/test/resources/JSONResponseToKeySetRequestMockBadRSAKey.json";
	protected String JSONMockResponseToTokenSetRequest_PATH = "C:/Users/wadel/eclipseWorkspaces/workspaceC-Spring/FirstGradle/src/test/resources/JSONResponseToTokenSetRequestMock.json";
	protected String JSONMockResponseToUserClaimsRequest_PATH = "C:/Users/wadel/eclipseWorkspaces/workspaceC-Spring/FirstGradle/src/test/resources/JSONResponseToUserClaimsRequestMock.json";

	protected String CALLBACK_ADDRESS = "http://localhost:8282/entry-point/OIDC-receive-auth-code";
	protected OpenIdConnClientInformation CLIENT_INFO = new OpenIdConnClientInformation(
				new ClientID("136188809562-nj33et1efshs5o643s1i8ddccbl9pf2j.apps.googleusercontent.com"),
				new Secret("Uf7af_GawLN6hCpv2pX0J4wk")
		);

//	public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().port(8383).httpsPort(8443));
	@Rule
	public WireMockRule wireMockRule = new WireMockRule(PROVIDER_PORT);

	protected OpenIdConnProviderConfig createConfigFixture() {
		// Note: Google wanted me to give the Redirect URI on the Credentials
		// screen of my project (Jadoub) in Cloud Console, even though
		// specification says we send with Auth redirect.
		 return OpenIdConnProviderConfigNimbus.fromEndPoint(
				 									PROVIDER_DOMAIN_AND_PORT,
													PROVIDER_CONFIG_ENDPOINT,
													CLIENT_INFO,
													CALLBACK_ADDRESS);		
	}

	protected void stubGetAtEndpointFor200JSONFromFile(String endpoint, 
													   String filePath)
													   throws IOException, URISyntaxException {
		String jsonResponse = getJSONMockResponseFromFile(filePath);
		stubFor(get(urlEqualTo(endpoint))
		//        .withHeader("Accept", equalTo("text/xml"))
		        .willReturn(aResponse()
		            .withStatus(200)
		            .withHeader("Content-Type", "application/json")
		            .withBody(jsonResponse)));
	}

	protected void stubPostWithBodyContainingAtEndpointFor200JSONFromFile(String endpoint, 
																		  String filePath, 
																		  String substring)
																		  throws IOException, URISyntaxException {
		String jsonResponse = getJSONMockResponseFromFile(filePath);
		stubFor(post(urlPathEqualTo(endpoint))
				.withRequestBody(containing(substring))
		        .willReturn(aResponse()
		            .withStatus(200)
		            .withHeader("Content-Type", "application/json")
		            .withBody(jsonResponse)));
	}

	public static class EndpointStubFromFileWithParameters {
		public String endpoint;
		public String filePath;
		public String paramKey;
		public String paramValue;

		public EndpointStubFromFileWithParameters(String endpoint,
				String filePath, String paramKey, String paramValue) {
			this.endpoint = endpoint;
			this.filePath = filePath;
			this.paramKey = paramKey;
			this.paramValue = paramValue;
		}
	}

	protected void stubGetWithQueryParamAtEndpointFor200JSONFromFile(EndpointStubFromFileWithParameters parameters)
																throws IOException, URISyntaxException {
		String jsonResponse = getJSONMockResponseFromFile(parameters.filePath);

		stubFor(get(urlPathEqualTo(parameters.endpoint))
			.withQueryParam(parameters.paramKey, equalTo(parameters.paramValue))
			.willReturn(aResponse()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(jsonResponse)));
}

	protected String getJSONMockResponseFromFile(String filePath)
			throws IOException, URISyntaxException {
				Path path = FileSystems.getDefault().getPath(filePath);
				List<String> lines = Files.readAllLines(path, Charset.defaultCharset());
				StringBuilder sb = new StringBuilder();
				for (String line : lines) {
					sb.append(line);
				}
				return sb.toString();
			}

}