<?php

interface iLogger {

	// Log an authentication attempt
	public function log_auth_attempt( $ip, $username, $success);
}
