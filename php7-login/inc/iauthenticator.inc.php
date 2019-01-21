<?php

interface iAuthenticator {

	// Perform authentication, with implicit password rehash
	public function authenticate( $username, $password);

	// Get tokens
	public function get_tokens( $username, &$tokens);

	// Check if you must perform 2nd factor authentication for user
	public function needs_2fa( $username);

	// Fetches the 2FA stored secret
	public function fetch_2fa_secret( $username);

	// Fetch profile from database
	public function fetch_credentials( $username);

	// Update tokens
	public function update_tokens( $username, $tokens);

	// Update password
	public function update_password( $username, $password);

	// Update the 2FA secrets if applicable
	public function update_2fa_secret( $username, $secret);
}
