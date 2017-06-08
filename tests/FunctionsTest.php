<?php
class FunctionsTest extends PHPUnit_Framework_TestCase
{

	public function testGetSbs_TwitterPostExample()
	{
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
		$result = oauth_get_sbs('POST', 'https://api.twitter.com/1/statuses/update.json', $params);

		$expected = 'POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521';
		self::assertEquals($expected, $result);
	}

	public function testGetSbs_UrlNormalization()
	{
		$params = array('alpha' => 'Z', 'charlie' => 'X', 'bravo' => 'A');
		$expectParams = 'alpha%3DZ%26bravo%3DA%26charlie%3DX';
		$result = oauth_get_sbs('GET', 'https://appcenter.intuit.com:8080/api/v1/Connection/Reconnect', array());
		self::assertEquals('GET&https%3A%2F%2Fappcenter.intuit.com%3A8080%2Fapi%2Fv1%2FConnection%2FReconnect&', $result);

		$result = oauth_get_sbs('GET', 'http://appcenter.intuit.com:80/api/v1/Connection/Reconnect', $params);
		self::assertEquals('GET&http%3A%2F%2Fappcenter.intuit.com%2Fapi%2Fv1%2FConnection%2FReconnect&' . $expectParams, $result);

		$result = oauth_get_sbs('GET', 'https://AppCenter.Intuit.com:443/api/v1/Connection/Reconnect', $params);
		self::assertEquals('GET&https%3A%2F%2Fappcenter.intuit.com%2Fapi%2Fv1%2FConnection%2FReconnect&' . $expectParams, $result);
	}

	public function testOauthUrlencode_TwitterExamples()
	{
		self::assertEquals('Ladies%20%2B%20Gentlemen', oauth_urlencode('Ladies + Gentlemen'));
		self::assertEquals('An%20encoded%20string%21', oauth_urlencode('An encoded string!'));
		self::assertEquals('Dogs%2C%20Cats%20%26%20Mice', oauth_urlencode('Dogs, Cats & Mice'));
		self::assertEquals('%E2%98%83', oauth_urlencode('☃'));
	}
}
