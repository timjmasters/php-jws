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

use PHPUnit\Framework\TestCase;
use TimJMasters\Base64URL\Base64URL;
use TimJMasters\JWS\JWS;

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
        $jws = JWS::createFromPayload($payload, $options);

        // Check the header
        $this->assertEquals($header, $jws->getHeader(), "The header is incorrect.");

        // Check the payload
        $this->assertEquals($payload, $jws->getPayload(), "The payload is incorrect.");

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
        $this->assertTrue(JWS::verify($jws, "foo_bar_12353253"), "The JWS doesn't have a valid signature for it's contents.");
    }

}
