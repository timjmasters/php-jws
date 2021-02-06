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

namespace TimJMasters\JWS;

use Exception;
use TimJMasters\Base64URL\Base64URL;

/**
 * A class for creating and verifying JWS objects
 */
class JWSUtil {

    const UNSECURED = "none";
    const HMAC_SHA256 = "HS256";
    const HMAC_SHA384 = "HS384";
    const HMAC_SHA512 = "HS512";
    const PAYLOAD_AS_JSON = "json_encode";
    const PAYLOAD_AS_STRING = "as_string";
    // Default options for creating JWS objects @see JWS::createFromPayload
    const DEFAULT_OPTIONS = [
        "header" => [
            "alg" => "HS256",
            "typ" => "JWT",
        ],
        "payload" => [
            "encoding" => self::PAYLOAD_AS_JSON,
            "encoding_options" => 0,
        ],
        "secret" => "",
    ];
    // Default allowed algorithms, don't use the none algorithm by default
    const DEFAULT_ALLOWED_ALGORITHMS = [
        self::HMAC_SHA256,
    ];

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
     *      <ul>
     *         <li>HS256</li>
     *         <li>none</li>
     *     </ul>
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
     *             </tr>
     *             <tr>
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
        $jws->setPayload(static::payloadToString($payload, $options["payload"]));

        // Create the signature using header values and the secret option
        $signature = static::makeSignature($jws, $options["secret"]);
        $jws->setSignature($signature);

        return $jws;
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

        // Set the header alg value, will be verified when signature is created
        if (!isset($header["alg"])) {
            $header["alg"] = self::HMAC_SHA256;
        }

        // Set the typ header value
        if (!isset($header["typ"])) {
            $header["typ"] = "JWT";
        }

        return $header;
    }

    /**
     * Create a signature from the header and payload using the alg specified
     * as well as the secret/key
     * @param string $secret the secret or key for the signing algorithm
     * @return string
     * @throws Exception
     */
    public static function makeSignature(JWS $jws, string $secret) {
        // Get the unsigned concatenation of header and payload
        $unsigned = $jws->getHeaderEncoded() . "." . $jws->getPayloadEncoded();

        // Sign the data based on the header options
        switch ($jws->getHeader()["alg"]) {
            // HMAC SHA 256
            case self::HMAC_SHA256:
                $signed = static::hmacSignature("sha256", $unsigned, $secret);
                break;

            // Empty string for unsecured jws
            case self::UNSECURED:
                $signed = "";
                break;

            // Throw an exception for unimplemented signature algorithms
            default:
                throw new Exception("The JWS algorithm specified isn't implemented.");
        }

        return $signed;
    }

    /**
     * Use HMAC to create the signature
     * @param string $alg
     * @param string $data
     * @param string $secret
     * @throws Exception if the hash failed
     */
    private static function hmacSignature($alg, $data, $secret) {

        $hash = hash_hmac($alg, $data, $secret, true);

        // Check it worked
        if (false === $hash) {
            throw new Exception("Couldn't hash data using algorithm: " . $alg);
        }
        return $hash;
    }

    /**
     * Merge options arrays (if the key exists in the default it will be overwritten)
     * @param array $default
     * @param array $supplied
     * @return type
     */
    private static function mergeOptions(array $default, array $supplied) {
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
     * Make the payload a string, using the payload_encoding option.
     * @return string
     * @throws Exception
     */
    private static function payloadToString($payload, array $options): string {
        switch ($options["encoding"]) {
            // JSON encode payload
            case self::PAYLOAD_AS_JSON:
                $payload = json_encode($payload, $options["encoding_options"]);
                if (false === $payload) {
                    throw new Exception("Couldn't JSON encode payload.");
                }
                return $payload;

            // Cast payload to string
            case self::PAYLOAD_AS_STRING:
                return (string) $payload;

            // Don't allow unsupported options
            default:
                throw new Exception("Not sure how to make Payload a string. Unknown payload_encoding option: " . $options["encoding"]);
        }
    }

    /**
     * Verify a JWS token is signed correctly. In the case of an unsecured JWS (alg = none)
     * the verification will fail if the jws has a signature, or a non-empty secret is supplied.
     * @param JWS $jws
     * @param string $secret the secret for hmac algorithms, or the public key for rsa algorithms
     * @param array $allowed_algorithms if supplied, the JWS will be rejected if its algorithm isn't in the $allowed_algorithms array
     * @return boolean true if the signature is valid, otherwise false.
     * @throws Exception if the algorithm is supported
     */
    public static function verify(JWS $jws, $secret = null, array $allowed_algorithms = self::DEFAULT_ALLOWED_ALGORITHMS) {
        $alg = $jws->getHeader()["alg"];

        // Check if the algorithm is permitted
        if ($allowed_algorithms && !in_array($alg, $allowed_algorithms)) {
            return false; //TODO use exceptions
        }

        // Verify based on which algorithm is specified
        switch ($alg) {
            case self::HMAC_SHA256:
                return static::hmacVerify($jws, $secret);
            case self::UNSECURED:
                return static::unsecuredVerify($jws, $secret);
            default:
                throw new Exception("Verification not implemented for alg: " . $jws->getHeader()["alg"]);
        }
    }

    private static function hmacVerify(JWS $jws, $secret) {
        $hash = Base64URL::encode(static::makeSignature($jws, $secret));

        if ($hash === $jws->getSignatureEncoded()) {
            return true;
        }
        return false;
    }

    private static function unsecuredVerify(JWS $jws, $secret) {
        $signature = $jws->getSignature();

        // If it's using the "none" algorithm, it shouldn't have a signature
        if ($signature) {
            //TODO use exceptions instead?
            return false;
        }

        // If we're using a secret, we aren't using the "none" algorithm
        if (!empty($secret)) {
            return false;
        }

        return true;
    }

    /**
     * Create JWS object from encoded JWS string. This doesn't necessarily 
     * create a JWS with a valid signature. It just uses what's supplied. 
     * Use the verify function to check it's validity.
     * 
     * @param string $token the encoded jws
     * @param boolean $json_decode Whether to json decode the payload.
     * @return JWS
     * @throws Exception if the string doesn't have 3 parts separated by .
     * TODO check the parts are Base64URL decoded correctly
     */
    public static function createFromEncoded(string $token, $json_decode = true) {
        $jws = new JWS();

        $parts = explode(".", $token);
        if (3 != count($parts)) {
            throw new Exception("String doesn't appear to be a JWS (couldn't get 3 parts separated by .)");
        }

        list($headerEncoded, $payloadEncoded, $signatureEncoded) = $parts;

        // Base64URL and json decode the header
        $jws->setHeader(json_decode(Base64URL::decode($headerEncoded), true));

        // Base64URL decode the payload
        $payload = Base64URL::decode($payloadEncoded);
        if ($json_decode) {
            $decoded = json_decode($payload, true);
            // Check we didn't have a decode fail
            if ($payload && !$decoded) {
                throw new \Exception("The payload couldn't be JSON decoded.");
            }
            $payload = $decoded;
        }
        $jws->setPayload($payload, $json_decode);

        // Base64URL decode the signature
        $jws->setSignature(Base64URL::decode($signatureEncoded));

        return $jws;
    }

}
