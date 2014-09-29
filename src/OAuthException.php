<?php
/**
 * @see http://php.net/manual/en/class.oauthexception.php
 */
class OAuthException extends Exception
{
	public $lastResponse;
	public $debugInfo;
}
