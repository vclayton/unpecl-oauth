unpecl-oauth
============

Native PHP drop-in replacement for the PECL OAuth extension

[![Build Status](https://travis-ci.org/vclayton/unpecl-oauth.svg?branch=master)](https://travis-ci.org/vclayton/unpecl-oauth)

### Debugging Info
There is a static OAuth::getDebugInfo() method that will return details about the most recent request. There will only be debug info if enableDebug() has been called.
```
/**
 * Returns debug info about the most recent fetch.
 * If no fetch has happened, debug info will be empty.
 * @param string $key  If given, return specific entry from debug info. Key is one of 'lastResponse', 'lastResponseInfo', 'lastResponseCode', or 'lastHeader'.
 * @return mixed  Returns a key/value array if key is not given, otherwise returns the specific key requested. If the key is not set, returns null.
 */
public static function getDebugInfo($key=null)
```

### Running tests
The unmodified upstream PECL tests are in tests/upstream. The ```runtests``` script patches and munges them into a more phpunit-friendly form, then runs them.

### TODO
* The OAuthProvider class has no upstream compliance tests, so it is not yet implemented.
* The setRequestEngine() call is currently ignored, only Curl is implemented.

### Notes
How to checkout the source code for the PECL OAuth extension:
```svn co https://svn.php.net/repository/pecl/oauth```

