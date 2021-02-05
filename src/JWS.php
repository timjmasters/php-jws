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

use Exception;
use TimJMasters\Base64URL\Base64URL;

class JWS {

    const HMAC_SHA256 = "HS256";
    const PAYLOAD_AS_JSON = "json_encode";
    const PAYLOAD_AS_STRING = "as_string";

    private $header;
    private $headerEncoded;
    private $payload;
    private $payloadEncoded;
    private $signature;
    private $signatureEncoded;

    const DEFAULT_OPTIONS = [
        "type" => "JWT",
        "algorithm" => "HS256",
        "header" => [],
        "payload" => [
            "encoding" => self::PAYLOAD_AS_JSON,
            "encoding_options" => null,
        ],
        "secret" => "",
    ];

    /**
     * Get the unencoded header
     * @return array
     */
    public function getHeader() {
        return $this->header;
    }

    /**
     * Encode the header
     */
    private function encodeHeader() {
        $this->headerEncoded = Base64URL::encode(json_encode($this->getHeader()));
    }

    /**
     * Set the header and encode it
     * @param array $header
     * @return $this
     */
    private function setHeader(array $header) {
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

    public function getPayload() {
        return $this->payload;
    }

    public function getPayloadEncoded() {
        return $this->payloadEncoded;
    }

    /**
     * Encode the payload
     */
    private function encodePayload(array $options) {
        $this->payloadEncoded = Base64URL::encode($this->payloadToString($options));
    }

    /**
     * Make the payload a string, using the payload_encoding option.
     * @return string
     * @throws Exception
     */
    private function payloadToString(array $options): string {
        switch ($options["encoding"]) {
            // JSON encode payload
            case self::PAYLOAD_AS_JSON:
                $payload = json_encode($this->getPayload(), $options["encoding_options"]);
                if (false === $payload) {
                    throw new Exception("Couldn't JSON encode payload.");
                }
                return $payload;

            // Cast payload to string
            case self::PAYLOAD_AS_STRING:
                return (string) $this->getPayload();

            // Don't allow unsupported options
            default:
                throw new Exception("Not sure how to make Payload a string. Unknown payload_encoding option: " . $this->payload_encoding);
        }
    }

    /**
     * Set the payload and encode it, and create the signature
     * @param mixed $payload
     * @return $this
     */
    private function setPayload($payload, $options) {
        // Set the values
        $this->payload = $payload;

        // The encode function will throw an exception if the encoding isn't supported.
        $this->encodePayload($options);
        return $this;
    }

    /**
     * Create the signature
     * @throws Exception if the alg header field isn't supported
     */
    private function makeSignature($secret) {
        // Get the unsigned concatenation of header and payload
        $unsigned = $this->getHeaderEncoded() . "." . $this->getPayloadEncoded();

        // Sign the data based on the header options
        switch ($this->getHeader()["alg"]) {
            // HMAC SHA 256
            case self::HMAC_SHA256:
                $signed = $this->hmacSignature("sha256", $unsigned, $secret);
                break;

            // Throw an exception for unimplemented signature algorithms
            default:
                throw new Exception("The JWS algorithm specified isn't implemented.");
        }

        // Set the value
        $this->signature = $signed;

        // Set the encoded value
        $this->signatureEncoded = Base64URL::encode($this->signature);
    }

    /**
     * Use HMAC to create the signature
     * @param string $alg
     * @param string $data
     * @param string $secret
     * @throws Exception if the hash failed
     */
    private function hmacSignature($alg, $data, $secret) {

        $hash = hash_hmac($alg, $data, $secret, true);

        // Check it worked
        if (false === $hash) {
            throw new Exception("Couldn't hash data using algorithm: " . $alg);
        }
        return $hash;
    }

    public function getSignature() {
        return $this->signature;
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

    /**
     * Create a JWS token
     * @param mixed $payload the payload for the JWS. See the payload_format option
     * @param array $options
     * <p>Available options:
     * <table>
     *  <tr>
     *   <td>type</td>
     *   <td><strong>Default: "JWT";</strong> The typ value for the JOSE header, if omitted or null will default to "JWT"</td>
     *  </tr>
     *  <tr>
     *   <td>algorithm</td>
     *   <td>
     *     <strong>Default: "HS256";</strong> The alg value for the JOSE header, if omitted or null will default to HS256 see <a href='https://tools.ietf.org/html/rfc7518'>rfc7518</a> For algorithm specifications. The signature will be created based on this value.
     *      Possible values:
     *     <table>
     *       <tr>
     *         <td>HS256</td>
     *         <td>none</td>
     *       </tr>
     *     </table>
     *   </td>
     *  </tr>
     *  <tr>
     *    <td>header</td><td>This allows setting the header manually, allowing for extra fields. These values take precedence over the defaults mentioned above.</td>
     *  </tr>
     *  <tr>
     *   <td>payload</td>
     *   <td>
     *     An array of options regarding the payload
     *     <table>
     *       <tr>
     *         <td>encoding</td>
     *         <td>
     *           <strong>Default: "json_encode";</strong> The format for the payload. Possible values:
     *           <table>
     *             <tr>
     *               <td>json_encode</td><td>The payload will be encoded using the json_encode function.</td>
     *               <td>as_string</td><td>The payload will be cast to a string and left as is.</td>
     *             </tr>
     *           </table>
     *         </td>
     *       </tr>
     *       <tr>
     *         <td>encoding_options</td>
     *         <td>Options for encoding functions if json_encode is used will be passed directly to the json_encode function.<td>
     *       </tr>
     *     </table>
     *    </td>
     *  </tr>
     *  <tr>
     *    <td>secret</td><td><strong>Default: "" (empty string);</strong> Supply a secret for the hashing function.</td>
     *  </tr>
     * </table>
     * </p>
     */
    public static function createFromPayload($payload, array $options = []): JWS {
        // Merge default options
        $options = static::mergeOptions(self::DEFAULT_OPTIONS, $options);

        // Create the header
        $header = static::createHeader($options);

        $jws = new JWS();

        // Set the header, it will be encoded as well
        $jws->setHeader($header);

        // Set the payload, it will be encoded as well
        $jws->setPayload($payload, $options["payload"]);

        // Create the signature using header values and the secret option
        $jws->makeSignature($options["secret"]);

        return $jws;
    }

    /**
     * Create JWS object from encoded JWS string. This doesn't necessarily 
     * create a JWS with a valid signature. It just uses what's supplied. 
     * Use the verify function to check it's validity.
     * 
     * @param string $string the encoded jws
     * @param boolean $json_decode Whether to json decode the payload.
     * @return JWS
     * @throws Exception if the string doesn't have 3 parts separated by .
     * TODO check the parts are Base64URL decoded correctly
     */
    public static function createFromEncoded(string $string, $json_decode = true) {
        $jws = new JWS();

        $parts = explode(".", $string);
        if (3 != count($parts)) {
            throw new Exception("String doesn't appear to be a JWS (couldn't get 3 parts separated by .)");
        }

        list($headerEncoded, $payloadEncoded, $signatureEncoded) = $parts;

        // Base64URL and json decode the header
        $jws->header = json_decode(Base64URL::decode($headerEncoded), true);
        $jws->headerEncoded = $headerEncoded;

        // Base64URL decode the payload
        $payload = Base64URL::decode($payloadEncoded);
        // Optionally json_decode the payload
        if ($json_decode) {
            $payload = json_decode($payload, true);
        }
        $jws->payloadEncoded = $payloadEncoded;

        // Base64URL decode the signature
        $jws->signature = Base64URL::decode($signatureEncoded);
        $jws->signatureEncoded = $signatureEncoded;

        return $jws;
    }

    private static function mergeOptions($default, $supplied) {
        foreach ($supplied as $k => $v) {
            // If it's an array, recurse otherwise just override the value
            if (isset($default[$k]) && is_array($v)) {
                $default[$k] = static::mergeOptions($default[$k], $v);
            } else {
                $default[$k] = $v;
            }
        }

        return $default;
    }

    /**
     * Create the header from the options supplied
     * @param array $options
     * @throws Exception If the options has a non array header value.
     */
    private static function createHeader(array $options): array {
        // Check the header option is an array
        if (isset($options["header"]) && !is_array($options["header"])) {
            throw new Exception("header option must be an array");
        }

        $header = array_merge([], $options["header"]);

        // Set the typ header value
        if (!isset($header["typ"])) {
            $header["typ"] = $options["type"] ? $options["type"] : "JWT";
        }

        // Set the header alg value, will be verified when signature is created
        if (!isset($header["alg"])) {
            $header["alg"] = $options["algorithm"] ? $options["algorithm"] : self::HMAC_SHA256;
        }

        return $header;
    }

    /**
     * Verify a JWS token is signed correctly
     * @param JWS $jws
     * @param string $secret the secret for hmac algorithms
     * @return boolean true if the signature is valid, otherwise false.
     * @throws Exception if the algorithm is supported
     */
    public static function verify(JWS $jws, $secret) {
        switch ($jws->getHeader()["alg"]) {
            case self::HMAC_SHA256:
                return static::hmacVerify($jws, $secret);
            default:
                throw new Exception("Verification not implemented for alg: " . $jws->getHeader()["alg"]);
        }
    }

    private static function hmacVerify(JWS $jws, $secret) {
        $hash = Base64URL::encode($jws->makeSignature($secret));

        if ($hash === $jws->getSignatureEncoded()) {
            return true;
        }
        return false;
    }

}
