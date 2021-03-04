<?php

/*
 * Copyright (C) 2020 Timothy John Masters timothy.john.masters@gmail.com
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

namespace TimJMasters\JWS;

use InvalidArgumentException;
use TimJMasters\Base64URL\Base64URL;

class JWS {

    private $header;
    private $headerEncoded;
    private $payload;
    private $payloadEncoded;
    private $signature;
    private $signatureEncoded;

    public function __construct() {
        $calling = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1];

        if (JWSUtil::class != $calling["class"]) {
            trigger_error("JWS objects aren't intended to be instantiated directly. Use the JWSUtil class to create JWS objects.", E_USER_WARNING);
        }
    }

    /**
     * Get the header (not encoded)
     * @return array
     */
    public function getHeader() {
        return $this->header;
    }

    /**
     * Encode the header
     */
    private function encodeHeader() {
        $this->headerEncoded = Base64URL::encode(json_encode($this->getHeader(), JSON_UNESCAPED_SLASHES));
    }

    /**
     * Set the header and encode it
     * @param array $header
     * @return $this
     */
    public function setHeader(array $header) {
        $this->header = $header;
        $this->encodeHeader();
        return $this;
    }

    /**
     * @return string The Base64URL encoded header
     */
    public function getHeaderEncoded() {
        return $this->headerEncoded;
    }

    public function getPayload($json_decode = false) {
        if ($json_decode) {
            return json_decode($this->payload, true);
        }
        return $this->payload;
    }

    public function getPayloadEncoded() {
        return $this->payloadEncoded;
    }

    /**
     * Set the payload and update encoded payload
     * @param mixed $payload
     * @param bool json_encode whether to json_encode the payload
     * @return $this
     */
    public function setPayload($payload, $json_encode = false) {
        $this->payload = $payload;
        if ($json_encode) {
            $this->payloadEncoded = Base64URL::encode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        } else {
            if (!is_string($payload)) {
                throw new InvalidArgumentException("Can only set strings as payloads. Use the json_encode parameter or serialize your payload as a string.");
            }
            $this->payloadEncoded = Base64URL::encode((string)$payload);
        }
        return $this;
    }

    public function getSignature() {
        return $this->signature;
    }

    public function setSignature($signature) {
        $this->signature = $signature;
        $this->signatureEncoded = Base64URL::encode($signature);
        return $this;
    }

    public function getSignatureEncoded() {
        return $this->signatureEncoded;
    }

    public function getEncoded() {
        return $this->getHeaderEncoded()
                . "." . $this->getPayloadEncoded()
                . "." . $this->getSignatureEncoded();
    }

    public function __toString() {
        return $this->getEncoded();
    }

}
