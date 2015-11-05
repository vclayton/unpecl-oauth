<?php
if (!function_exists('oauth_get_sbs')) {
	define("OAUTH_USER_AGENT", "PECL-OAuth/0.1-unpecl");
	define("OAUTH_MAX_HEADER_LEN", 512);

	define("OAUTH_AUTH_TYPE_URI", 0x01);
	define("OAUTH_AUTH_TYPE_FORM", 0x02);
	define("OAUTH_AUTH_TYPE_AUTHORIZATION", 0x03);
	define("OAUTH_AUTH_TYPE_NONE", 0x04);

	define("OAUTH_SIG_METHOD_HMACSHA1", "HMAC-SHA1");
	define("OAUTH_SIG_METHOD_HMACSHA256", "HMAC-SHA256");
	define("OAUTH_SIG_METHOD_RSASHA1", "RSA-SHA1");
	define("OAUTH_SIG_METHOD_PLAINTEXT", "PLAINTEXT");

	define("OAUTH_HTTP_METHOD_GET", "GET");
	define("OAUTH_HTTP_METHOD_POST", "POST");
	define("OAUTH_HTTP_METHOD_PUT", "PUT");
	define("OAUTH_HTTP_METHOD_HEAD", "HEAD");
	define("OAUTH_HTTP_METHOD_DELETE", "DELETE");

	define("OAUTH_REQENGINE_STREAMS", 1);
	define("OAUTH_REQENGINE_CURL", 2);

	define("OAUTH_SSLCHECK_NONE", 0x00);
	define("OAUTH_SSLCHECK_HOST", 0x01);
	define("OAUTH_SSLCHECK_PEER", 0x02);
	define("OAUTH_SSLCHECK_BOTH", 0x03);

	function oauth_get_sbs($http_method, $uri, $request_parameters=null)
	{
		$request_parameters = ($request_parameters === null ? array() : $request_parameters);
		if (!is_array($request_parameters)) {
			trigger_error('oauth_get_sbs() expects parameter 3 to be array, ' . gettype($request_parameters) . ' given', E_USER_WARNING);
			return null;
		}

		list($uriBase) = explode('?', strtolower($uri), 2);

		parse_str(parse_url($uri, PHP_URL_QUERY), $query_params);
		$params = $query_params + $request_parameters;

		$params = array_diff_key($params, array('oauth_signature' => 1));

		$normalizedParams = array();
		foreach ($params as $key => $value) {
			$normalizedParams[urlencode($key)] = urlencode($value);
		}
		uksort($normalizedParams, 'strnatcmp');
		$paramParts = array();
		foreach ($normalizedParams as $key => $value) {
			$paramParts[] = $key . '=' . $value;
		}
		$param_str = implode('&', $paramParts);

		return $http_method . '&' . urlencode($uriBase) . '&' . urlencode($param_str);
	}

	function oauth_urlencode($uri)
	{
		return rawurlencode($uri);
	}
}
