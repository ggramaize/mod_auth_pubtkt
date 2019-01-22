<?php

interface iAuthenticator {

	// Fully bypasses the authentication logic provided in the shipped
	// authentication module.
	//
	// This method may be used if your authentication mechanism already
	// has built-in password validation and refreshing.
	//
	// When not implemented, this method SHALL return null.
	// When implemented, it SHALL return true when user AND password
	// matches. It MUST return false in any other case
	public function authenticate( $username, $password);

	// Get tokens
	public function get_tokens( $username, &$tokens);

	// Check if you must perform 2nd factor authentication for user
	public function needs_2fa( $username);

	// Fetches the 2FA stored secret
	public function fetch_2fa_secret( $username);

	// Fetch profile from database
	public function fetch_profile( $username);

	// Update tokens
	public function update_tokens( $username, $tokens);

	// Update password
	public function update_password( $username, $password);

	// Update the 2FA secrets if applicable
	public function update_2fa_secret( $username, $secret);
}
