<?php

require __DIR__ . '/../vendor/autoload.php';

if (!class_exists('PHPUnit_Framework_TestCase')) {
	class_alias('PHPUnit\Framework\TestCase', 'PHPUnit_Framework_TestCase');
	class_alias('PHPUnit\Util\PHP\DefaultPhpProcess', 'PHPUnit_Util_PHP');
}
