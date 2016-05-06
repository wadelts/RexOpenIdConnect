package com.rexcanium.oidc.nimbus;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.interfaces.RSAPublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder;
import com.rexcanium.oidc.OpenIdConnAuthenticationRequest;
import com.rexcanium.oidc.OpenIdConnProvider;
import com.rexcanium.oidc.OpenIdConnProviderConfig;
import com.rexcanium.oidc.OpenIdConnProviderException;
import com.rexcanium.oidc.OpenIdConnTokenSet;

/**
 * Nimbus implementation of OpenIdConnProvider interface, allowing us
 * query the Provider to retrieve IdTokens, AccessTokens, RefreshTokens
 * and additional User Information.
 * 
 * @author wadel
 *
 */
public class OpenIdConnProviderNimbus implements OpenIdConnProvider {
	private static final Logger logger = LoggerFactory.getLogger(OpenIdConnProviderNimbus.class);

	private OpenIdConnProviderConfig providerConfig;
	
	private OpenIdConnProviderNimbus(OpenIdConnProviderConfig providerConfig) {
		this.providerConfig = providerConfig;
	}
	
	public static OpenIdConnProvider fromConfiguration(OpenIdConnProviderConfig providerConfig) {
		return new OpenIdConnProviderNimbus(providerConfig);
	}

	@Override
	public URI generateAuthenticationRequestRedirectURI(OpenIdConnAuthenticationRequest authenticationRequestInfo) {
		
		// Compose the request
		AuthenticationRequest authenticationRequest = new AuthenticationRequest(
				providerConfig.getAuthorizationEndpointURI(),
				new ResponseType(ResponseType.Value.CODE),
				authenticationRequestInfo.getScope(),
				new ClientID(providerConfig.getClientID()), 
				providerConfig.getRedirectCallBackURI(), 
				authenticationRequestInfo.getState(), 
				authenticationRequestInfo.getNonce()); // make nonce null - not required for Code Flow version (i.e. backend server-to-server retrieval of iDtoken)

		return convertedToURI(authenticationRequest);
	}

	private URI convertedToURI(AuthenticationRequest authenticationRequest) {
		try {
			return authenticationRequest.toURI();
		} catch (SerializeException e) {
			logger.error("convertToURI: Error trying to compose Issuer Authorization EndPoint URI. Exception was: " + e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.convertToURI: Error trying to compose Issuer Authorization EndPoint URI", e);
		}
	}

	@Override
	public String extractCodeFromRequestURL(String requestURLFromProvider, OpenIdConnAuthenticationRequest retainedAuthenticationRequestInfo) {
		
		AuthenticationResponse authResp = parseAuthenticationResponse(requestURLFromProvider);
		AuthenticationSuccessResponse successResponse = authenticationResponseEstablishedAsSuccess(authResp);

		verifyStatesMatch(retainedAuthenticationRequestInfo.getState(), successResponse.getState());

		return successResponse.getAuthorizationCode().toString();
	}

	private AuthenticationResponse parseAuthenticationResponse(String requestURLFromProvider) {
		try {
			return AuthenticationResponseParser.parse(new URI(requestURLFromProvider));
		} catch (ParseException | URISyntaxException e) {
			logger.error("parseAuthenticationResponse: Error trying to parse AuthorizationCode from return Request URL. Exception was: " + e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.parseAuthenticationResponse: Error trying to parse AuthorizationCode from return Request URL", e);
		}
	}

	private AuthenticationSuccessResponse authenticationResponseEstablishedAsSuccess(AuthenticationResponse authResp) {
		if (authResp instanceof AuthenticationErrorResponse) {
			ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
			String errorMessage = String.format("OpenIdConnProviderNimbus.establishedAuthenticationSuccessResponse: Error returned by the Provider in return Request URL. ErrorCode: %s Description: %s HTTPStatusCode: %s URI: %s", error.getCode(), error.getDescription(), error.getHTTPStatusCode(), error.getURI());
			logger.error(errorMessage);
			throw new OpenIdConnProviderException(errorMessage);
		} else {
			return (AuthenticationSuccessResponse) authResp;
		}
	}

	/**
	 * The state in the received authentication response must match the state
	 * specified in the previous outgoing authentication request.
	 * 
	 * @param retainedState the state kept by server
	 * @param returnedState the state returned by Provider
	 */
	private void verifyStatesMatch(State retainedState, State returnedState) {
		if (! retainedState.equals(returnedState)) {
			String errorMessage = String.format("OpenIdConnProviderNimbus.verifyStatesMatch: The State value was found to be different than expected in the return Request URL. Expected: %s Found: %s", retainedState, returnedState);
			logger.error(errorMessage);
			throw new OpenIdConnProviderException(errorMessage);
		}
	}
	
	@Override
	public OpenIdConnTokenSet retrieveTokenSetFromProvider(String authCode) {

		TokenRequest tokenReq = buildTokenRequest(authCode);
		HTTPResponse tokenHTTPResp = submitTokenRequest(tokenReq);
		TokenResponse tokenResponse = parseTokenResponse(tokenHTTPResp);
		
		OIDCAccessTokenResponse accessTokenResponse = tokenResponseEstablishedAsSuccess(tokenResponse);
		verifyIdToken(accessTokenResponse.getIDToken());
		
		return new OpenIdConnTokenSet(accessTokenResponse.getIDToken(),
									  accessTokenResponse.getAccessToken(),
									  accessTokenResponse.getRefreshToken());
	}

	private TokenRequest buildTokenRequest(String authCode) {
		AuthorizationCode authorizationCode = new AuthorizationCode(authCode);
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(new ClientID(providerConfig.getClientID()), new Secret(providerConfig.getClientSecret()));
		AuthorizationCodeGrant authorizationCodeGrant = new AuthorizationCodeGrant(authorizationCode, providerConfig.getRedirectCallBackURI());
		
		TokenRequest tokenReq = new TokenRequest(providerConfig.getTokenEndpointURI(),
												 clientSecretBasic,
												 authorizationCodeGrant);
		return tokenReq;
	}
	
	private HTTPResponse submitTokenRequest(TokenRequest tokenReq) {
		HTTPResponse tokenHTTPResp = null;
		try {
			tokenHTTPResp = tokenReq.toHTTPRequest().send();
			logger.info("submitTokenRequest: Response Content was\n" + tokenHTTPResp.getContent());
		} catch (SerializeException | IOException e) {
			logger.error("submitTokenRequest: Token request to Provider failed. Error was: " + e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.submitTokenRequest: Token request to Provider failed.", e);
		}
		return tokenHTTPResp;
	}

	private TokenResponse parseTokenResponse(HTTPResponse tokenHTTPResp) {
		TokenResponse tokenResponse = null;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
		} catch (ParseException e) {
			logger.error("parseTokenResponse: Error trying to parse Token response from Provider.", e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.parseTokenResponse: Error trying to parse Token response from Provider.", e);
		}
		return tokenResponse;
	}

	private OIDCAccessTokenResponse tokenResponseEstablishedAsSuccess(TokenResponse tokenResponse) {
		if (tokenResponse instanceof TokenErrorResponse) {
			ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
			if (error == null) {
				logger.error("establishedTokenRequestSuccessResponse: Error returned by the Provider. Was TokenErrorResponse but ErrorObject not available!");
				throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.establishedTokenRequestSuccessResponse: Error returned by the Provider. Was TokenErrorResponse but ErrorObject not available!");
			}
			else {
				String errorMessage = String.format("OpenIdConnProviderNimbus.establishedTokenRequestSuccessResponse: Error returned by the Provider. ErrorCode: %s Description: %s HTTPStatusCode: %s URI: %s", error.getCode(), error.getDescription(), error.getHTTPStatusCode(), error.getURI());
				logger.error(errorMessage);
				throw new OpenIdConnProviderException(errorMessage);
			}
		} else {
			return (OIDCAccessTokenResponse) tokenResponse;
		}
	}

	private ReadOnlyJWTClaimsSet verifyIdToken(JWT idToken) {
		
		DefaultJWTDecoder jwtDecoder = createJWTDecoder(idToken);
		
		return verifiedClaims(idToken, jwtDecoder);
	}

	private DefaultJWTDecoder createJWTDecoder(JWT idToken) {
		String kidOfKeyUsedToHashThisMsg = getKeyIdFromHeader(idToken);
		RSAPublicKey publicKeyUsedToHashThisMsg = providerConfig.getProviderKey(kidOfKeyUsedToHashThisMsg);
		
		DefaultJWTDecoder jwtDecoder = new DefaultJWTDecoder();
		jwtDecoder.addJWSVerifier(new RSASSAVerifier(publicKeyUsedToHashThisMsg));
		
		return jwtDecoder;
	}

	private String getKeyIdFromHeader(JWT idToken) {
		String kidOfKeyUsedToHashThisMsg = "";
		JSONObject header = idToken.getHeader().toJSONObject();
		
		Object kidOfKeyUsedToHashThisMsgObj = header.get("kid");
		if (kidOfKeyUsedToHashThisMsgObj != null) {
			kidOfKeyUsedToHashThisMsg = (String) kidOfKeyUsedToHashThisMsgObj;
		}
		
		return kidOfKeyUsedToHashThisMsg;
	}

	private ReadOnlyJWTClaimsSet verifiedClaims(JWT idToken, DefaultJWTDecoder jwtDecoder) {
		try {
		    return jwtDecoder.decodeJWT(idToken);
		} catch (JOSEException e) {
			logger.error("verifiedClaims: Error trying to validate or deccrypt IDToken returned from Provider. Token=" + idToken.getParsedString() + " Error was: " + e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.verifiedClaims: Error trying to validate or deccrypt IDToken returned from Provider. ", e);
		} catch (java.text.ParseException e) {
			logger.error("verifiedClaims: Error trying to parse IDToken returned from Provider. Token=" + idToken.getParsedString() + " Error was: " + e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.verifiedClaims: Error trying to parse IDToken returned from Provider.", e);
		}
	}

	/*
	 * Claims (used by OpenId Connect protocol) and
	 * UserInfo (used by Nimbus) are synonymous.
	 * 
	 */
	@Override
	public JSONObject retrieveUserClaimsFromProvider(JSONObject token) {

		UserInfoRequest userInfoReq = createClaimsRequest(token);
		HTTPResponse userInfoHTTPResp = submitClaimsRequest(userInfoReq);
		UserInfoResponse userInfoResponse = parseClaimsResponse(userInfoHTTPResp);

		UserInfoSuccessResponse successResponse = claimsResponseEstablishedAsSuccess(userInfoResponse);

		return successResponse.getUserInfo().toJSONObject();
	}

	private UserInfoRequest createClaimsRequest(JSONObject token) {
		BearerAccessToken accessToken = parseAccessToken(token);
		
		UserInfoRequest userInfoReq = new UserInfoRequest(providerConfig.getUserInfoEndpointURI(),
														  accessToken);
		return userInfoReq;
	}

	private BearerAccessToken parseAccessToken(JSONObject token) {
		try {
			return (BearerAccessToken) AccessToken.parse(token);
		} catch (ParseException e) {
			logger.error("parseAccessToken: Error trying to parse Access Token: " + token.toString() + e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.parseAccessToken: Error trying to parse Access Token: " + token.toString() + e);
		}
	}

	private HTTPResponse submitClaimsRequest(UserInfoRequest userInfoReq) {
		HTTPResponse userInfoHTTPResp = null;
		try {
			userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
			logger.info("submitClaimsRequest: Response Content was\n" + userInfoHTTPResp.getContent());
		} catch (SerializeException | IOException e) {
			logger.error("submitClaimsRequest: Error trying to send UserInfoRequest to Provider. Error was: " + e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.submitClaimsRequest: Error trying to send UserInfoRequest to Provider: " + e);
		}
		return userInfoHTTPResp;
	}

	private UserInfoResponse parseClaimsResponse(HTTPResponse userInfoHTTPResp) {
		UserInfoResponse userInfoResponse = null;
		try {
		  userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);
		} catch (ParseException e) {
			logger.error("parseClaimsResponse: Error trying parse userInfoResponse from Provider: " + e);
			throw new OpenIdConnProviderException("OpenIdConnProviderNimbus.parseClaimsResponse: Error trying parse userInfoResponse from Provider: " + e);
		}
		return userInfoResponse;
	}

	private UserInfoSuccessResponse claimsResponseEstablishedAsSuccess(UserInfoResponse userInfoResponse) {
		if (userInfoResponse instanceof UserInfoErrorResponse) {
			ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
			String errorMessage = String.format("OpenIdConnProviderNimbus.retrieveUserClaimsFromProvider: Error returned by the Provider in Response when trying to retrieve User Claims. ErrorCode: %s Description: %s HTTPStatusCode: %s URI: %s", error.getCode(), error.getDescription(), error.getHTTPStatusCode(), error.getURI());
			logger.error(errorMessage);
			throw new OpenIdConnProviderException(errorMessage);
		} else {
			return (UserInfoSuccessResponse) userInfoResponse;
		}
	}

}
