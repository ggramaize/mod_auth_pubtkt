<?php

class AuthenticationModule {
	// Selected authentication module
	private $auth_module;
	private $allow_legacy_authentication;

	public function step1_authenticate( $username, $password)
	{
		if( $username === null || $password === null)
			return false;

		// Check if the authentication provider bypass our logic. If so, delegate.
		if( $this->$auth_module->authenticate( null, null) !== null )
			return $this->$auth_module->authenticate( $username, $password);

		// Fetch profile data
		if( $user_profile = $this->$auth_module->fetch_profile( $username) === null )
			return false;	
		
		// Check password using the proper method
		if( password_verify( $password, $user_profile['password']) === true )
		{
			// Check if we need to rehash the password
			if( password_needs_rehash( $user_profile['password'], PASSWORD_DEFAULT) === true )
			{
				$new_hash = password_hash( $password, PASSWORD_DEFAULT);
				$this->$auth_module->update_password( $username, $new_hash);
				$user_profile['password'] = $new_hash;
			}
			return true;
		}

		// Check password according to the unsafe legacy mechanism, then rehash the password 
		if( $allow_legacy_authentication === true && ( md5($password) === $user_profile['password'] || $password === $user_profile['password'] ))
		{
			$new_hash = password_hash( $password, PASSWORD_DEFAULT);
			$this->$auth_module->update_password( $username, $new_hash);
			$user_profile['password'] = $new_hash;	
			return true;
		}

		return false;
	}

	public function step2_authenticate( $response)
	{

	}

}
