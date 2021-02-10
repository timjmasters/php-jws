<?php

/*
 * Copyright (C) 2021 Timothy Masters <timothy.john.masters@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace Tests\TimJMasters\JWS;

use Exception;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use stdClass;
use TimJMasters\Base64URL\Base64URL;
use TimJMasters\JWS\JWS;
use TimJMasters\JWS\JWSUtil;

class JWSTest extends TestCase {

    public function testDummyJWS() {
        $header = [
            "alg" => "HS256",
            "typ" => "JWT",
        ];
        $payload = [
            "sub" => "1234567890",
            "name" => "John Doe",
            "iat" => 1516239022
        ];
        $options = [
            "header" => $header,
            "secret" => "foo_bar_12353253",
        ];

        // Create a token
        $jws = JWSUtil::createFromPayload($payload, $options);

        // Check the header
        $this->assertEquals($header, $jws->getHeader(), "The header is incorrect.");

        // Check the payload
        $this->assertEquals($payload, $jws->getPayload(true), "The payload is incorrect.");

        // Check the signature
        $this->assertEquals(Base64URL::decode("WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZPAk"), $jws->getSignature(), "The signature doesn't appear to be correct.");

        // Check header encoded
        $this->assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", $jws->getHeaderEncoded(), "The encoded header appears to be incorrect.");

        // Check payload encoded
        $this->assertEquals("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", $jws->getPayloadEncoded(), "The encoded payload appears to be incorrect.");

        // Check jws encoded
        $this->assertEquals(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZPAk",
                $jws->getEncoded(),
                "The encoded JWS appears to be incorrect."
        );

        // Check string cast
        $this->assertEquals(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZPAk",
                (string) $jws,
                "The result of casting to string appears to be incorrect."
        );
    }

    public function testCreateFromEncoded() {
        $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZPAk";

        // Create the jws
        $jws = JWSUtil::createFromEncoded($token);

        //TODO test invalid token
        // Check the signature
        $this->assertEquals(Base64URL::decode("WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZPAk"), $jws->getSignature(), "The signature doesn't appear to be correct.");

        // Check header encoded
        $this->assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", $jws->getHeaderEncoded(), "The encoded header appears to be incorrect.");

        // Check payload encoded
        $this->assertEquals("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", $jws->getPayloadEncoded(), "The encoded payload appears to be incorrect.");

        // Check jws encoded
        $this->assertEquals(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZPAk",
                $jws->getEncoded(),
                "The encoded JWS appears to be incorrect."
        );

        // Check Verification
        $this->assertTrue(JWSUtil::verify($jws, "foo_bar_12353253"), "The JWS doesn't have a valid signature for it's contents.");

        // TODO test json_decode option
    }

    public function testAlteredSignature() {
        // Create the jws
        $jws = JWSUtil::createFromEncoded("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZP");

        // Check the signature
        $this->assertEquals(Base64URL::decode("WUphQgEfGvtdUCw4UntIh__bemKY6eDFjX2K2XCZP"), $jws->getSignature(), "The signature doesn't appear to be correct.");

        // Check header encoded
        $this->assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", $jws->getHeaderEncoded(), "The encoded header appears to be incorrect.");

        // Check payload encoded
        $this->assertEquals("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", $jws->getPayloadEncoded(), "The encoded payload appears to be incorrect.");

        // Check Verification fails
        $this->assertFalse(JWSUtil::verify($jws, "foo_bar_12353253"), "The JWS shouldn't be valid.");
    }

    public function testUnsecuredJWS() {
        $jws = JWSUtil::createFromPayload([
                    "foo" => "bar",
                        ], [
                    "header" => [
                        "alg" => "none",
                    ]
        ]);

        // We don't allow the none algorithm by default
        $this->assertFalse(JWSUtil::verify($jws), "The none algorithm shouldn't be allowed by default.");

        // If your application does for some reason use the none algorithm, 
        // and you don't pass a secret to the verify function when you're 
        // expecting a secure token, attackers can create a token with the none
        // alg field and you could be in trouble. It's not recommended you allow
        // the none algorithm unless your tokens don't need to be secure.
        // The following should pass as the signature is empty, the
        // algorithm is none, and none is permitted
        $this->assertTrue(JWSUtil::verify($jws, null, ["none", "HS256"]));
    }

    public function testAlteredToUnsecure() {
        $secret = "foobar123";
        $payload = [
            "foo" => "bar",
        ];
        $options = [
            "header" => [
                "alg" => "HS256",
                "typ" => "JWT",
            ],
            "secret" => $secret,
        ];

        $jws = JWSUtil::createFromPayload($payload, $options);

        // Get the original signature
        $og_signature = $jws->getSignature();
        $og_signature_encoded = $jws->getSignatureEncoded();

        // Create an altered header
        $alteredHeader = [
            "alg" => "none",
            "typ" => "JWT",
        ];

        $jws->setHeader($alteredHeader);

        // Check it still has its signature
        $this->assertNotEmpty($jws->getSignature(), "The JWS should still have its signature.");
        $this->assertEquals($og_signature, $jws->getSignature(), "The JWS signature changed.");
        $this->assertEquals($og_signature_encoded, $jws->getSignatureEncoded(), "The JWS encoded signature changed.");

        // Verification should fail if the JWS has a signature and a none algorithm
        $this->assertFalse(JWSUtil::verify($jws), "The JWS shouldn't verify with a none algorithm and a signature.");

        // Remove the signature and it should still fail if a secret is provided
        $jws->setSignature(null);
        $this->assertEmpty($jws->getSignature());
        $this->assertEmpty($jws->getSignatureEncoded());

        // Verification should fail since the JWS has no signature but a secret is passed to the verify function
        $this->assertFalse(JWSUtil::verify($jws, $secret, ["none", "HS256"]));

        // Verification should still fail if none isn't in the allowed_algorithms
        $this->assertFalse(JWSUtil::verify($jws, null, ["HS256"]));

        // If your application does for some reason use the none algorithm, 
        // and you don't pass a secret to the verify function when you're 
        // expecting a secure token, attackers can create a token with the none
        // alg field and you could be in trouble. <strong>It's not recommended you allow
        // the none algorithm.</strong>
        // The following should pass as the signature has been removed, the
        // algorithm has been changed to none, and none is permitted
        $this->assertTrue(JWSUtil::verify($jws, null, ["none", "HS256"]));
    }

    public function testJSONEncodedPayloads() {
        $payload = [
            "foo" => "bar",
        ];

        // Create a jws from the payload, doesn't matter what alg so we'll just use HS256 with a secret of foo
        // We'll supply the JSON_encoding option
        $secret = "foo";
        $header = [
            "alg" => "HS256",
        ];
        $options = [
            "header" => $header,
            "payload" => [
                "encoding" => "json_encode",
            ]
        ];
        $jws = JWSUtil::createFromPayload($payload, $options);

        // If we fetch the payload without JSON_decoding it (the default behaviour) we should get a JSON string
        $this->assertNotNull(json_decode($jws->getPayload()), "The payload isn't valid JSON: " . json_last_error_msg());

        // If we fetch the payload and decode it, we should get an array
        $this->assertIsArray($jws->getPayload(true), "The payload should be returned as an array.");

        // If we set the payload to something that isn't valid JSON and don't JSON encode it
        $jws->setPayload("This is a string which isn't valid JSON { foo = bar }");
        // We shouldn't get valid JSON back, we should get the original string
        $this->assertEquals("This is a string which isn't valid JSON { foo = bar }", $jws->getPayload(), "The payload isn't what it should be.");
        $this->assertNull(json_decode($jws->getPayload()), "The payload shouldn't be valid JSON");

        // If we try and JSON decode we should get a null result //TODO this should probably throw an exception
        $this->assertNull($jws->getPayload(true), "The payload shouldn't be JSON decodable.");

        // Create a JWS token with valid JSON payload but encoded ourself
        $jws2 = JWSUtil::createFromPayload('{"foo": "bar"}', [
                    "header" => $header,
                    "payload" => [
                        "encoding" => "as_string", // Don't JSON encode
                    ]
        ]);

        // If we fetch the payload without json_decoding it (the default behaviour) we should get a JSON string
        $this->assertNotNull(json_decode($jws2->getPayload()), "The payload isn't valid JSON: " . json_last_error_msg() . "(" . $jws->getPayload() . ")");

        // If we fetch the payload and decode it, we should get an array
        $this->assertIsArray($jws2->getPayload(true), "The payload should be returned as an array.");
        $this->assertEquals($payload, $jws2->getPayload(true), "The payload appears incorrect.");
    }

    public function testInstantiationError() {
        // Check that instantiating a JWS triggers an error
        $this->expectTriggeredWarning();
        $jws = new JWS();
    }

    public function testInvalidPayload() {
        // If payload is invalid, invalid argument exception should be thrown
        $this->expectException(InvalidArgumentException::class);

        $jws = JWSUtil::createFromPayload([]);

        // Try setting an object that can't be cast to string
        $jws->setPayload(new stdClass());
    }

    public function testDefaultOptions() {
        $jws = JWSUtil::createFromPayload([], []);

        $this->assertEquals("HS256", $jws->getHeader()["alg"]);
        $this->assertEquals("JWT", $jws->getHeader()["typ"]);
    }

    public function testInvalidHeader1() {
        $this->expectException(\Exception::class);
        $jws = JWSUtil::createFromPayload([], [
                    "header" => false,
        ]);
    }

    public function testDefaultHeader() {
        $jws = JWSUtil::createFromPayload([], [
                    "header" => [
                        "alg" => false,
                        "typ" => false,
                    ],
        ]);
        
        $this->assertEquals("HS256", $jws->getHeader()["alg"]);
        $this->assertEquals("JWT", $jws->getHeader()["typ"]);
    }

    private function expectTriggeredWarning() {
        $this->expectException(ExpectedTriggeredWarningException::class);
        $this->expectTriggered(E_WARNING | E_USER_WARNING);
    }

    private function expectTriggered($expected) {
        $previous = null;
        $previous = set_error_handler(function($errno, $errstr, $errfile = null, $errline = null, $errcontext = null) use($previous, $expected): bool {
            if (0 == ($expected & $errno)) {
                if ($previous) {
                    return $previous($errno, $errstr, $errfile, $errline, $errcontext);
                }
                return false;
            }

            switch ($errno) {
                case E_WARNING:
                case E_USER_WARNING:
                    throw new ExpectedTriggeredWarningException();
            }
            return true;
        });
    }

}

class ExpectedTriggeredWarningException extends Exception {
    
}
