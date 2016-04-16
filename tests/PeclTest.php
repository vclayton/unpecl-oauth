<?php
/**
 * If some bugs were fixed in PHPUnit_Extensions_PhptTestCase we could just use that.
 * This is essentially a stripped-down copy of that, with whitespace problems fixed.
 */
class PeclTest extends PHPUnit_Framework_TestCase
{
	protected $settings = array(
		'allow_url_fopen=1',
		'auto_append_file=',
		'auto_prepend_file=',
		'disable_functions=',
		'display_errors=1',
		'docref_root=',
		'docref_ext=.html',
		'error_append_string=',
		'error_prepend_string=',
		'error_reporting=-1',
		'html_errors=0',
		'log_errors=0',
		'magic_quotes_runtime=0',
		'output_handler=',
		'open_basedir=',
		'output_buffering=Off',
		'report_memleaks=0',
		'report_zend_debug=0',
		'safe_mode=0',
		'track_errors=1',
		'xdebug.default_enable=0'
	);

	public function loadTestCases()
	{
		$tests = array();
		$files = glob("tests/pecl/*.phpt");
		foreach ($files as $file) {
			$raw = file_get_contents($file);
			if (getenv("CURL_AGENT_ORDER")) {
				$raw = str_replace("User-Agent: PECL-OAuth/%f%s\nHost: 127.0.0.1:12342", "Host: 127.0.0.1:12342\nUser-Agent: PECL-OAuth/%f%s", $raw);
			}

			$sections = array('FILENAME' => "'" . $file . "'", 'DIRNAME' => "'" . dirname($file) . "'");
			$splits = preg_split('/--([A-Z]+)--\n/', $raw, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
			while (count($splits) > 1) {
				$sections[array_shift($splits)] = array_shift($splits);
			}
			$tests[basename($file)] = array($sections);
		}
		return $tests;
	}

	/**
	 * @dataProvider loadTestCases
	 */
	public function testCases($sections)
	{
        $php  = PHPUnit_Util_PHP::factory();

		if (isset($sections['SKIPIF'])) {
			$jobResult = $php->runJob($sections['SKIPIF'], $this->settings);

			if (!strncasecmp('skip', ltrim($jobResult['stdout']), 4)) {
				if (preg_match('/^\s*skip\s*(.+)\s*/i', $jobResult['stdout'], $message)) {
					$message = substr($message[1], 2);
				} else {
					$message = '';
				}
				self::markTestSkipped($message);
			}
		}

		$code = strtr($sections['FILE'], array(
			'__DIR__' => $sections['DIRNAME'],
			'__FILE__' => $sections['FILENAME'],
		));

		$jobResult = $php->runJob($code, $this->settings);
		$output = preg_replace('/\r\n/', "\n", trim($jobResult['stdout']));
		if (isset($sections['EXPECT'])) {
			self::assertEquals(preg_replace('/\r\n/', "\n", trim($sections['EXPECT'])), $output);
		} else {
			self::assertStringMatchesFormat(preg_replace('/\r\n/', "\n", trim($sections['EXPECTF'])), $output);
		}
	}

}