<?php
class OAuthTest extends PHPUnit_Framework_TestCase
{

	public function testTwitterPostExample()
	{
		$postParams = array(
			'status' => 'Hello Ladies + Gentlemen, a signed OAuth request!',
		);
		$params = array(
			'include_entities' => 'true',
			'status' => 'Hello Ladies + Gentlemen, a signed OAuth request!',
			'oauth_consumer_key' => 'xvz1evFS4wEEPTGEFPHBog',
			'oauth_nonce' => 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg',
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' => 1318622958,
			'oauth_token' => '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb',
			'oauth_version' => '1.0',
		);
		$consumerKey = 'xvz1evFS4wEEPTGEFPHBog';
		$consumerSecret = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw';
		$token = '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb';
		$tokenSecret = 'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE';
		$oauth = $this->getMock('OAuth', array('execCurl'), array($consumerKey, $consumerSecret, OAUTH_SIG_METHOD_HMACSHA1));
		$oauth->setToken($token, $tokenSecret);
		$result = $oauth->generateSignature('POST', 'https://api.twitter.com/1/statuses/update.json', $params);

		$expected = 'tnnArxj06cWHq44gCs1OSKk/jLY=';
		self::assertEquals($expected, $result);

		$oauth->setFlags(OAuth::FLAG_SORT_AUTHORIZATION); 
		$oauth->setNonce('kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg');
		$oauth->setTimestamp(1318622958);
		$fullUrl = 'https://api.twitter.com/1/statuses/update.json?include_entities=true';
		$expectAuthHeader = 'Authorization: OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog",oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1318622958",oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",oauth_version="1.0"';
		$expectCurl = array(
			CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_0,
			CURLOPT_RETURNTRANSFER => 1,
			CURLINFO_HEADER_OUT    => 1,
			CURLOPT_HTTPHEADER     => array(
				$expectAuthHeader,
			),
			CURLOPT_CUSTOMREQUEST  => 'POST',
			CURLOPT_HEADERFUNCTION => array($oauth, '_curlReceiveHeader'),
			CURLOPT_SSL_VERIFYPEER => OAUTH_SSLCHECK_PEER,
			CURLOPT_SSL_VERIFYHOST => 2,
			CURLOPT_USERAGENT      => OAUTH_USER_AGENT,
		);

		$oauth->expects(self::once())->method('execCurl')
			->with($fullUrl, $expectCurl)
			->will(self::returnValue(array('OK', array('http_code' => '200'))));
		$oauth->fetch($fullUrl, $postParams, 'POST');
	}

	public function testNouncerExample()
	{
		$url = 'http://photos.example.net/photos';
		$fullUrl = "{$url}?file=vacation.jpg&size=original";

		$oauth = $this->getMock('OAuth', array('oauth_get_sbs', 'execCurl'), array('dpf43f3p2l4k3l03', 'kd94hf93k423kf44', OAUTH_SIG_METHOD_HMACSHA1));
		$oauth->setToken('nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00');
		$oauth->setNonce('kllo9940pd9333jh');
		$oauth->setTimestamp('1191242096');

		$sbsParams = array(
			'oauth_consumer_key'     => 'dpf43f3p2l4k3l03',
			'oauth_token'            => 'nnch734d00sl2jdk',
			'oauth_nonce'            => 'kllo9940pd9333jh',
			'oauth_timestamp'        => '1191242096',
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_version'          => '1.0',
			'size'                   => 'original',
			'file'                   => 'vacation.jpg',
		);
		$expectSbs = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal';
		self::assertEquals($expectSbs, oauth_get_sbs('GET', $url, $sbsParams));
		$oauth->expects(self::exactly(2))->method('oauth_get_sbs')
			->with('GET', $url, $sbsParams)
			->will(self::returnValue($expectSbs));

		$signature = $oauth->generateSignature('GET', $url, $sbsParams);
		self::assertEquals('tR3+Ty81lMeYAr/Fid0kMTYa/WM=', $signature);

		// The realm param is optional. Parameter order is not restricted by the spec, but it's easier to read when sorted.
		// $expectAuthHeader = 'Authorization: OAuth realm="http://photos.example.net/photos",oauth_consumer_key="dpf43f3p2l4k3l03",oauth_token="nnch734d00sl2jdk",oauth_nonce="kllo9940pd9333jh",oauth_timestamp="1191242096",oauth_signature_method="HMAC-SHA1",oauth_version="1.0",oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"';
		$expectAuthHeader = 'Authorization: OAuth oauth_consumer_key="dpf43f3p2l4k3l03",oauth_nonce="kllo9940pd9333jh",oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1191242096",oauth_token="nnch734d00sl2jdk",oauth_version="1.0"';
		$oauth->setFlags(OAuth::FLAG_SORT_AUTHORIZATION); 

		$expectCurl = array(
			CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_0,
			CURLOPT_RETURNTRANSFER => 1,
			CURLINFO_HEADER_OUT    => 1,
			CURLOPT_HTTPHEADER     => array(
				$expectAuthHeader,
				'Expect:',
			),
			CURLOPT_CUSTOMREQUEST  => 'GET',
			CURLOPT_HEADERFUNCTION => array($oauth, '_curlReceiveHeader'),
			CURLOPT_SSL_VERIFYPEER => OAUTH_SSLCHECK_PEER,
			CURLOPT_SSL_VERIFYHOST => 2,
			CURLOPT_USERAGENT      => OAUTH_USER_AGENT,
		);

		$oauth->expects(self::once())->method('execCurl')
			->with($fullUrl, $expectCurl)
			->will(self::returnValue(array('OK', array('http_code' => '200'))));
		$oauth->fetch($fullUrl);
	}
}