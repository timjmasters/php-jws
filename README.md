[![Travis-ci build status](https://img.shields.io/travis/com/timjmasters/php-jws?style=for-the-badge)](https://travis-ci.com/timjmasters/php-jws)
[![License](https://img.shields.io/github/license/timjmasters/php-jws?color=blue&style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0.en.html)
[![Code coverage](https://img.shields.io/coveralls/github/timjmasters/php-jws?style=for-the-badge)](https://coveralls.io/github/timjmasters/php-jws)

# php-jws
Some JWS Tools for PHP - authored by Timothy John Masters

This code was written more as a learning/practice exercise, the [firebase/php-jwt](https://github.com/firebase/php-jwt) is likely to be much more complete and feature rich.

Currently only supports JWS compact serialization with no intention of implementing a JWS JSON serialization solution.
## Installation
Install as a dependency using composer, then use the composer autoloader:
`composer require timjmasters/php-jws`

## Usage
Use the JWSUtil class to create and verify JWS tokens.

### JWSUtil - utility class for creating and verifying JWS objects
 - `JWSUtil::createFromPayload($payload, array $options) : JWS`
    Creates a JWS object using the specified payload and options, including encoding the parts and signing the token:
   - **header**: set any header fields you need, defaults to `["alg" => "HS256", "typ" => "JWT"] ` see below for supported algorithms
   - **payload**: an array of options regarding the payload:
     - **encoding**: either **json_encoding** or **as_string** (default: json_encoding)
       If 'json_encoding' is used, the payload will be JSON encoded before being set on the object, so the object's getPayload() method will return a JSON encoded string unless the json_decode argument is supplied.
       If 'as_string' is used the payload will be cast to a string before being set on the object.
     - **encoding_options**: Options to pass to the json_encode function if used eg JSON_PRETTY_PRINT (default: 0)
   - **secret**: a secret or key to use for creating the signature
 - `JWSUtil::createFromEncoded(string $token, bool $json_decode) : JWS`
    Creates a JWS object from an encoded JWS string, if the $json_decode argument is true, the payload will be decoded before being set, an exception will be thrown if the payload cannot be decoded.
    The signature is set as supplied, so make sure you verify the token before you trust it.
 - `JWSUtil::verify(JWS $jws, $secret, array $allowed_algorithms)`
   Verify that a JWS token's signature matches it's contents. Returns false if the token signature isn't verified.
   - The header's algorithm isn't in the supplied allowed algorithms (default: ["HS256", "RS256"])
   - If HMAC:
     - The base64url encoded json encoded header concatenated with a single period and the base64url encoded payload (optionally json encoded when the token was created) is hashed using the secret provided and the result is compared to the token's signature
   - If RSA:
     - The openssl_verify function is used to verify that the token's signature is valid for the base64url encoded json encoded header concatenated with a single period and the base64url encoded payload (optionally json encoded when the token is created)
     - The public key should be provided in the $secret parameter, it can be a string or a resource identifier created using an openssl function.

### JWS
The object has methods for viewing data encoded in the token.
It's not recommended you use the setters directly, rather create tokens using the JWSUtil class.
 - `$jws->getHeader()`
   - Get the header as an array typically something like ['alg' => 'RS256', 'typ' => 'JWT']
 - `$jws->getPayload($json_decode = false)`
   - Get the payload, the optional json_decode parameter is a convenience in case the payload wasn't encoded during token creation ie. using the 'as_string' encoding option but is still valid json which you'd like decoded.
   - The payload doesn't necessarily need to be a json string or array, it could be binary data
 - `$jws->getSignature()`
   - Get the unencoded signature, usually a hash or binary string
 - `$jws->getHeaderEncoded()`
   - Get the JWS header as a base64url encoded json encoded string
 - `$jws->getPayloadEncoded()`
   - Get the payload base64url encoded
   - The payload can optionally be encoded when set
 - `$jws->getSignatureEncoded()`
   - Get the signature base64url encoded
 - `$jws->getEncoded()`
   - Get all the encoded parts concatenated with periods between. eg eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZP
   - Equivalent to `$jws->getHeaderEncoded() . '.' . $jws->getPayloadEncoded() . '.' . $jws->getSignatureEncoded`
 - `$jws->setHeader(array $header)`
   - Set the JWS header
   - The encoded value will be updated and the signature won't match if the header has changed
 - `$jws->setPayload($payload, $json_encode = false)`
   - Set the payload, optionally encode it as a json string
   - The encoded value will be updated and the signature won't match if the payload has changed
 - `$jws->setSignature($signature)`
   - Set the signature
   - Not checked against the header and payload, not recommended you use this directly

## Notes
#### Currently supported algorithms
 - HS256
   - HMAC SHA 256 - JWS tokens will be signed using the secret option
 - RS256
   - RSA SHA 256 - JWS tokens will be signed assuming the secret option is a private key


## Examples
### Create a JWS object from an array, json encode it
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
// Will output eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.U_rA2byM9Nw_zrXNZfAqEOuyqCO75B9iHh6yO-Fjjgg
// You can also get the header or payload as an array using the $jws->getHeader() or $jws->getPayload() methods.

```


### Create a JWS object using RS256

```php
use TimJMasters\JWS\JWSUtil;

$private_key = openssl_pkey_get_private("path/to/your/private/key.pem");
$public_key = openssl_pkey_get_public("path/to/your/public/key.pem");
// Or you could do:
// $private_key = file_get_contents("path/to/your/private/key.pem");
// $public_key = file_get_contents("path/to/your/public/key.pem");

// Options for creating the token
$options = [
    "header" => [
        "alg" => JWSUtil::RSA_SHA256, // 'RS256'
        "typ" => "JWT",
    ],
    "secret" => $private_key,
];

// Create the token
$jws = JWSUtil::createFromPayload(["foo" => "bar"], $options);

print $jws; // eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.SIGNATURE_ACCORDING_TO_YOUR_CERTIFICATES

var_export(JWSUtil::verify($jws, $public_key, ["RS256"])); // true

```

### Verify a token from Google

```php
use TimJMasters\JWS\JWSUtil;

// Assuming we have a token from google we can create a JWS object
$id_token = JWSUtil::createFromEncoded($google_token);

// Make sure you follow verification according to https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken as the library only checks the signature.

// Get the key location from the jwks_uri in the Discovery document, use an HTTP library or curl to make the requests to Google.
$jwks_uri = json_decode(http_get_request('https://accounts.google.com/.well-known/openid-configuration'), true)['jwsk_uri']; // Currently https://www.googleapis.com/oauth2/v3/certs as of 2021/03/04

$google_keys = json_decode(http_get_request($jwks_uri), true); // Gives an array of keys

// Search the array for the correct kid according to the value in the token header
$key_info = array_search($idToken->getHeader()['kid'], array_column($google_keys, "kid"));

// You should probably check the key algorithm matches the token algorithm, but I won't show that here as using the $key_info['alg'] value as the only allowed algorithm effectively does that.

// Google currently uses RSA keys, you need to get the public key based on the modulus and exponent provided.
// I won't show how to do this here, but you might use the phpseclib library, or the firebase/php-jwt source as a way of calculating it here: https://github.com/firebase/php-jwt/blob/f42c9110abe98dd6cfe9053c49bc86acc70b2d23/src/JWK.php#L116
$public_key = createKeyFrom($key_info["n"], $key_info["e"]);

var_export(JWSUtil::verify($id_token, $public_key, [$key_info['alg']])); // Prints true or false

```
