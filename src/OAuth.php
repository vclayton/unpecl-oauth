<?php
/**
 * This is meant to be a drop-in replacement for the PECL OAuth extension, with some extra debugging capabilities.
 * @see http://php.net/manual/en/class.oauth.php
 */
class OAuth
{
	// From Pecl
	const FETCH_USETOKEN       = 1;
	const FETCH_SIGONLY        = 2;
	const FETCH_HEADONLY       = 4;
	const OVERRIDE_HTTP_METHOD = 8;
	// Not from Pecl
	const FETCH_SORTAUTH       = 64;

	public $debug = false;
	public $debugInfo = false;
	public $sslChecks = OAUTH_SSLCHECK_BOTH;

	protected $consumer_key;
	protected $consumer_secret;
	protected $token;
	protected $token_secret;
	protected $signature_method;
	protected $timestamp;
	protected $nonce;
	protected $oauthVersion = "1.0";
	protected $rsaCert;
	protected $auth_type;
	protected $requestEngine = OAUTH_REQENGINE_CURL;

	protected $lastResponse = '';
	protected $lastResponseInfo = array();
	protected $lastHeader = '';
	protected $lastHeaders = array();
	protected $flags = 0;

	protected static $lastDebugInfo = false;

	/**
	 * Returns debug info about the most recent fetch.
	 * If no fetch has happened, debug info will be empty.
	 * @param string $key  If given, return specific entry from debug info. Key is one of 'lastResponse', 'lastResponseInfo', 'lastResponseCode', or 'lastHeader'.
	 * @return mixed  Returns a key/value array if key is not given, otherwise returns the specific key requested. If the key is not set, returns null.
	 */
	public static function getDebugInfo($key=null)
	{
		if ($key) {
			return array_key_exists($key, self::$lastDebugInfo) ? self::$lastDebugInfo[$key] : null;
		}
		return self::$lastDebugInfo;
	}

	public function __construct($consumer_key=null, $consumer_secret=null, $signature_method=OAUTH_SIG_METHOD_HMACSHA1, $auth_type=OAUTH_AUTH_TYPE_AUTHORIZATION)
	{
		if (empty($consumer_key)) {
			throw new Exception("The consumer key cannot be empty", -1);
		}
		if (empty($consumer_secret)) {
			throw new Exception("The consumer secret cannot be empty", -1);
		}
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;
		$this->signature_method = $signature_method;
		$this->setAuthType($auth_type);
	}

	public function setToken($token, $token_secret)
	{
		$this->token = $token;
		$this->token_secret = $token_secret;
	}

	public function setTimestamp($timestamp)
	{
		return $this->timestamp = $timestamp;
	}

	public function setNonce($nonce)
	{
		return $this->nonce = $nonce;
	}

	public function disableDebug()
	{
		$this->debug = false;
	}

	public function enableDebug()
	{
		$this->debug = true;
	}

	public function setFlags($flags)
	{
		$this->flags = $flags;
	}

	public function setAuthType($auth_type)
	{
		switch ($auth_type) {
			case OAUTH_AUTH_TYPE_URI:
			case OAUTH_AUTH_TYPE_FORM:
			case OAUTH_AUTH_TYPE_AUTHORIZATION:
			case OAUTH_AUTH_TYPE_NONE:
				$this->auth_type = $auth_type;
				break;
			default:
				throw new Exception("Invalid auth type", 503);
		}
		return true;
	}

	public function disableSSLChecks()
	{
		$this->sslChecks = OAUTH_SSLCHECK_NONE;
	}

	public function enableSSLChecks()
	{
		$this->sslChecks = OAUTH_SSLCHECK_BOTH;
	}

	public function setRequestEngine($reqengine)
	{
		$this->requestEngine = $reqengine;
	}

	public function fetch($protected_resource_url, $extra_parameters=array(), $http_method=OAUTH_HTTP_METHOD_GET, array $http_headers=array(), $oauth_args=array(), $flags=0)
	{
		$queryStr = parse_url($protected_resource_url, PHP_URL_QUERY);
		parse_str($queryStr, $queryParams);
		$normalizedUrl = preg_replace('/\?.*/', '', $protected_resource_url);

		$signatureKeys = array(
			'consumer_key' => $this->consumer_key,
			'shared_secret' => $this->consumer_secret,
			'oauth_token' => $this->token,
			'oauth_secret' => $this->token_secret,
		);

		$oauthParams = array(
			'oauth_consumer_key' => $this->consumer_key,
			'oauth_signature_method' => $this->signature_method,
			'oauth_nonce' => $this->nonce ?: uniqid().'.'.time(),
			'oauth_timestamp' => $this->timestamp ?: time(),
			'oauth_version' => $this->oauthVersion,
		);
		if (!empty($this->token)) {
			$oauthParams['oauth_token'] = $this->token;
		}
		$oauthParams = array_merge($oauthParams, $oauth_args);
		$signParams = array_merge($queryParams, is_array($extra_parameters) ? $extra_parameters : array(), $oauthParams);

		$signature = $this->_generateSignature($http_method, $normalizedUrl, $signParams);
		if ($flags & self::FETCH_SIGONLY) {
			return $signature;
		}


		$requestParams = $extra_parameters;
		switch ($this->auth_type) {
			case OAUTH_AUTH_TYPE_URI:
				$requestParams = $oauthParams + $extra_parameters + array('oauth_signature' => $signature);
				break;

			case OAUTH_AUTH_TYPE_AUTHORIZATION:
				$auth = 'OAuth ';
				$oauthParams['oauth_signature'] = $signature;
				if ($this->flags & self::FETCH_SORTAUTH) {
					ksort($oauthParams);
				}
				foreach ($oauthParams as $key => $value) {
					$auth .= oauth_urlencode($key) . '="' . oauth_urlencode($value) . '",';
				}
				$http_headers['Authorization'] = rtrim($auth, ',');
				break;

			case OAUTH_AUTH_TYPE_FORM:
				$extra_parameters = http_build_query($oauthParams + array('oauth_signature' => $signature));
				break;
		}

		$url = $protected_resource_url;
		if (!empty($requestParams) && is_array($requestParams) && empty($queryParams)) {
			$url .= '?' . http_build_query($requestParams);
		}

		foreach ($http_headers as $name => $value) {
			$curlHeaders[] = "$name: $value";
		}
		if (!isset($http_headers['Accept']) && $this->requestEngine != OAUTH_REQENGINE_CURL) {
			$curlHeaders[] = "Accept:"; // Prevent curl's default 'Accept: */*'
		}
		if ($http_method != 'POST') {
			$curlHeaders[] = "Expect:";
		}

		$curlOptions = array();
		if ($this->requestEngine == OAUTH_REQENGINE_CURL) {
			$curlOptions[CURLOPT_USERAGENT] = OAUTH_USER_AGENT;
		}
		$curlOptions = $curlOptions + array(
			CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_0,
			CURLOPT_RETURNTRANSFER => 1,
			CURLINFO_HEADER_OUT    => 1,
			CURLOPT_HTTPHEADER     => $curlHeaders,
			CURLOPT_CUSTOMREQUEST  => $http_method,
			CURLOPT_HEADERFUNCTION => array($this, '_curlReceiveHeader'),
			CURLOPT_SSL_VERIFYPEER => $this->sslChecks & OAUTH_SSLCHECK_PEER,
			CURLOPT_SSL_VERIFYHOST => ($this->sslChecks & OAUTH_SSLCHECK_HOST) ? 2 : 0,
		);
		if (is_string($extra_parameters)) {
			$curlOptions[CURLOPT_POSTFIELDS] = $extra_parameters;
		} elseif (is_array($extra_parameters) && !empty($extra_parameters)) {
			$curlOptions[CURLOPT_POSTFIELDS] = $this->http_build_query($extra_parameters);
		}

		$this->lastHeader = false;
		list($this->lastResponse, $this->lastResponseInfo) = $this->execCurl($url, $curlOptions);
		$responseCode = $this->lastResponseInfo['http_code'];

		if ($this->debug) {
			$this->debugInfo = array(
				'lastResponse' => $this->lastResponse,
				'lastResponseInfo' => $this->lastResponseInfo,
				'lastResponseCode' => $responseCode,
				'lastHeader' => $this->lastHeader,
			);
			self::$lastDebugInfo = $this->debugInfo;
		}

		if ($responseCode > 300 && $responseCode < 304) {
			$redirectUrl = substr($this->lastResponseInfo['redirect_url'], 0, OAUTH_MAX_HEADER_LEN - 1);
			return $this->fetch($redirectUrl);
		} elseif ($responseCode < 200 || $responseCode > 209) {
			$e = new OAuthException("Invalid auth/bad request (got a {$responseCode}, expected HTTP/1.1 20X or a redirect)", $responseCode);
			$e->lastResponse = $this->lastResponse;
			$e->debugInfo = $this->lastResponseInfo;
			throw $e;
		}

		return true;
	}


	public function generateSignature($http_method, $url, $extra_parameters=array())
	{
		return $this->fetch($url, $extra_parameters, $http_method, array(), array(), self::FETCH_SIGONLY);
	}

	public function getLastResponse()
	{
		return $this->lastResponse;
	}

	public function getLastResponseHeaders()
	{
		return $this->lastHeader;
	}

	public function getLastResponseInfo()
	{
		return $this->lastResponseInfo;
	}

	/**
	 * The $http_method parameter is undocumented
	 */
	public function getAccessToken($access_token_url, $auth_session_handle=null, $verifier_token=null, $http_method=OAUTH_HTTP_METHOD_POST)
	{
		$params = array(
			'oauth_token' => $this->token,
		);
		if (!$verifier_token && isset($_REQUEST['oauth_verifier'])) {
			$verifier_token = $_REQUEST['oauth_verifier'];
		}
		if ($verifier_token) {
			$params['oauth_verifier'] = $verifier_token;
		}
		$headers = ($this->requestEngine !== OAUTH_REQENGINE_CURL) ? array('Connection' => 'close') : array();
		$this->fetch($access_token_url, array(), $http_method, $headers, $params);
		$response = $this->getLastResponse();
		parse_str($response, $result);
		return $result;
	}

	/**
	 * The $http_method parameter is undocumented
	 */
	public function getRequestToken($request_token_url, $callback_url=null, $http_method=OAUTH_HTTP_METHOD_POST)
	{
		$params = array();
		$oauthArgs = array();
		if (isset($callback_url)) {
			$oauthArgs['oauth_callback'] = empty($callback_url) ? "oob" : $callback_url;
		}
		$headers = ($this->requestEngine !== OAUTH_REQENGINE_CURL) ? array('Connection' => 'close') : array();
		$this->fetch($request_token_url, $params, $http_method, $headers, $oauthArgs);
		$response = $this->getLastResponse();
		parse_str($response, $result);
		return $result;
	}

	public function setRSACertificate($cert)
	{
		$this->rsaCert = openssl_pkey_get_private($cert);
		return !!$this->rsaCert;
	}

	/**
	 * Sets the timeout for HTTP requests, in milliseconds.
	 * This is an undocumented and unlisted function.
	 * @param integer $timeout  The HTTP timeout, in milliseconds
	 * @return Returns true on success, or false on failure.
	 */
	public function setTimeout($timeout)
	{
		if ($timeout < 0) {
			throw new Exception("Invalid timeout", 503);
		}
		return true;
	}

	public function setVersion($version='1.0')
	{
		if (!func_num_args()) {
			trigger_error('OAuth::setVersion() expects exactly 1 parameter, 0 given', E_USER_WARNING);
			return null;
		}
		if (empty($version)) {
			throw new Exception("Invalid version", 503);
		}
		$this->oauthVersion = $version;
		return true;
	}

	/**
	 * Proper encoding for PHP version <= 5.3
	 */
	public function http_build_query($params, $separator='&')
	{
		$query = '';
		$prevSeparator = '';
		foreach ($params as $key => $value) {
			$query .= $prevSeparator . oauth_urlencode($key) . '=' . oauth_urlencode($value);
			$prevSeparator = $separator;
		}
		return $query;
	}

	/**
	 * This method records header data as it is received by curl
	 * It is only public because it must be callable by curl
	 */
	public function _curlReceiveHeader($curl, $header)
	{
		$this->lastHeader .= $header;
		return strlen($header);
	}


	protected function _generateSignature($http_method, $url, $signParams)
	{
		$signatureBase = $this->oauth_get_sbs($http_method, $url, $signParams);
		$secretKeys = $this->consumer_secret.'&'.$this->token_secret;

		$rawSignature = null;
		switch ($this->signature_method) {
			case OAUTH_SIG_METHOD_PLAINTEXT:
				return $secretKeys;
			case OAUTH_SIG_METHOD_HMACSHA1:
				$rawSignature = hash_hmac('sha1', $signatureBase, $secretKeys, TRUE);
				break;
			case OAUTH_SIG_METHOD_HMACSHA256:
				$rawSignature = hash_hmac('sha256', $signatureBase, $secretKeys, TRUE);
				break;
			case OAUTH_SIG_METHOD_RSASHA1:
				// @todo Exception if no OpenSSL
				openssl_sign($signatureBase, $rawSignature, $this->rsaCert, OPENSSL_ALGO_SHA1);
				break;
			default:
				throw new OAuthException("Invalid Signature Method");
		}
		return base64_encode($rawSignature);
	}

	// Protected wrapper to allow mocking
	protected function oauth_get_sbs($http_method, $uri, $request_parameters=null)
	{
		return oauth_get_sbs($http_method, $uri, $request_parameters);
	}

	protected function execCurl($url, $curlOptions)
	{
		$ch = curl_init($url);
		curl_setopt_array($ch, $curlOptions);
		$lastResponse = curl_exec($ch);
		$lastResponseInfo = curl_getinfo($ch);
		return array($lastResponse, $lastResponseInfo);
	}

}

