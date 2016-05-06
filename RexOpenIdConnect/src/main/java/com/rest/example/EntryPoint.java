package com.rest.example;


import java.io.IOException;
import java.net.URI;
import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import net.minidev.json.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.rest.example.service.OIDCService;
import com.rest.example.service.OIDCServiceImpl;
import com.rexcanium.oidc.OpenIdConnTokenSet;
 
@Path("/entry-point")
public class EntryPoint {
 
    private static final Logger logger = LoggerFactory.getLogger(EntryPoint.class);
	
	private OIDCService oidcService = new OIDCServiceImpl();
	
    @GET
    @Path("test")
    @Produces(MediaType.TEXT_PLAIN)
    public String test() {
        return "Test";
    }

    @GET
    @Path("initiate-dummy")
    @Produces(MediaType.TEXT_PLAIN)
	public String initiateDummy(@Context HttpServletRequest request) {
		
    	String returningURL = getFullURL(request);
		logger.info("initiateDummy: returningURL=" + returningURL);
		try {
			String returningBody = convertToString(request.getInputStream());
			logger.info("initiateDummy: len= " + returningBody.length() + " returningBody=" + returningBody);
		} catch (IOException e) {
			logger.info("Exception: {}", e);
		}

		URI redirectAuthURI = oidcService.generateAuthenticationRequestRedirectURI();
		
		return "Redirect URI would be: " + redirectAuthURI.toString();
	}

    @GET
    @Path("initiate")
	public Response initiate() {
		
		URI redirectAuthURI = oidcService.generateAuthenticationRequestRedirectURI();
		
		return Response.temporaryRedirect(redirectAuthURI).build();
	}
	
    @GET
    @Path("OIDC-receive-auth-code")
    @Produces(MediaType.TEXT_PLAIN)
	public String receiveAuthCode(@Context HttpServletRequest request) {

    	String returningURL = getFullURL(request);
		logger.info("receiveAuthCode: returningURL=" + returningURL);
		try {
			String returningBody = convertToString(request.getInputStream());
			logger.info("receiveAuthCode: len= " + returningBody.length() + " returningBody=" + returningBody);
		} catch (IOException e) {
			logger.info("Exception: {}", e);
		}

		
		String authorizationCode = oidcService.extractCodeFromRequestURL(returningURL);
		logger.info("receiveAuthCode: authorizationCode=" + authorizationCode.toString());
		
		OpenIdConnTokenSet tokenSet =  oidcService.retrieveTokenSetFromProvider(authorizationCode);
		
		logger.info("receiveAuthCode: IDToken=" + tokenSet.getIDToken().toString());
		
		// Note: I included "email" scope in the authorisation request, in OpenIdConnProviderNimbus
		String claims = "No claims in JWT";
		String header = "No header in JWT";
		try {
			claims = tokenSet.getIDToken().getJWTClaimsSet().toJSONObject().toString();
			header = tokenSet.getIDToken().getHeader().toJSONObject().toString();
		} catch (ParseException e) {
			logger.info("receiveAuthCode: Exception parsing JWT claims or header: " + e);
		}
		logger.info("receiveAuthCode: claims=" + claims);
		logger.info("receiveAuthCode: header=" + header);

		JSONObject userClaims = oidcService.retrieveUserClaimsFromProvider(tokenSet.getAccessToken().toJSONObject());

		return "OIDC-receive-auth-code processed code returned by Provider. authorizationCode was: " + authorizationCode.toString() + " ID Token header: " + header + " ID Token Claims: " + claims + "\n userClaims=\n" + userClaims.toString();
	}
	
	private static String getFullURL(HttpServletRequest request) {
	    StringBuffer requestURL = request.getRequestURL();
	    String queryString = request.getQueryString();

	    String fullURL = null;
	    if (queryString == null) {
	    	fullURL = requestURL.toString();
	    } else {
	    	fullURL = requestURL.append('?').append(queryString).toString();
	    }
	    
	    return fullURL;
	}
	
    private static String convertToString(java.io.InputStream is) {
	    @SuppressWarnings("resource") // is actually assigned (from useDelimiter return value) and closed
		java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
	    String dataAsString = s.hasNext() ? s.next() : "";
	    s.close();
	    try { is.close(); } catch (IOException e) {logger.info("Exception: {}", e); }
	    return dataAsString;
	}
}
