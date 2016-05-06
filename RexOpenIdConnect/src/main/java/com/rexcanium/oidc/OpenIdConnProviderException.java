package com.rexcanium.oidc;

public class OpenIdConnProviderException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Will create a new exception with the given reason.
	 * @param reason the text explaining the error
	 */
	public OpenIdConnProviderException(String reason) {
		super(reason);
	}

	/**
	 * Will create a new exception with the given reason, supplying the causing Exception.
	 * @param reason the text explaining the error
	 * @param cause the original Exception that caused the error
	 */
	public OpenIdConnProviderException(String reason, Throwable cause) {
		super(reason, cause);
	}
}
