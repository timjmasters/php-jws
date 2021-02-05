[![Travis (.com)](https://img.shields.io/travis/com/timjmasters/php-jws?style=for-the-badge)](https://travis-ci.com/timjmasters/php-base64url)
[![License](https://img.shields.io/github/license/timjmasters/php-jws?color=blue&style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0.en.html)

# php-jws
Some JWS Tools for PHP

# This document is incomplete sorry for the inconvenience

Currently only supports JWS compact serialization with no intention of implementing a JWS JSON serialization solution.
## Installation
Install as a dependency using composer:
`composer require timjmasters/php-jws`

## Usage
Use the JWSUtil class to create and verify JWS tokens.

 - `JWSUtil::createFromPayload($payload, $options)`
    Creates a JWS object using the specified payload and options, including encoding the parts and signing the token:
   - **header**: set any header fields you need, defaults to `["alg" => "HS256", "typ" => "JWT"] ` see below for supported algorithms
   - **payload**: an array of options regarding the payload:
     - **encoding**: either **json_encoding** or **as_string** (default: json_encoding)
       If 'json_encoding' is used, the payload will be JSON encoded before being set on the object, so the object's getPayload() method will return a JSON encoded string unless the json_decode argument is supplied.
       If 'as_string' is used the payload will be cast to a string before being set on the object.
     - **encoding_options**: Options to pass to the json_encode function if used eg JSON_PRETTY_PRINT (default: 0)
   - **secret**: a secret or key to use for creating the signature
 - TODO

Create a JWS object from an array, json encode it:
```php
use TimJMasters\JWS\JWSUtil;

$jws = JWSUtil::createFromPayload(
    // The payload
    [
        "foo" => "bar"
    ],
    [
        "secret" => "foobar123",
        "payload" => [
            "encoding" => JWSUtil::PAYLOAD_AS_JSON      //"json_encode"
        ]
    ]
);

print $jws . "\r\n";
```