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
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use TimJMasters\JWS\JWSUtil;

class RSATest extends TestCase {

    private const CERT_DIR = __DIR__ . "/../var/ssh/";

    private $keys = [];

    public function testRS256() {
        $header = [
            "alg" => "RS256",
            "typ" => "JWT",
        ];
        $payload = [
            "foo" => "bar",
        ];
        $private = $this->getRS256PrivateKey();
        $public = $this->getRS256PublicKey();

        $options = [
            "header" => $header,
            "secret" => $private,
        ];

        $jws = JWSUtil::createFromPayload($payload, $options);
        $this->assertTrue(JWSUtil::verify($jws, $public, [JWSUtil::RSA_SHA256]), "The JWS didn't verify");
    }

    private function getRS256PrivateKey() {
        if (!realpath($this->getPrivate256KeyPath())) {
            $this->createRS256Certs();
        }

        $res = openssl_pkey_get_private("file://" . $this->getPrivate256KeyPath());

        if (!$res) {
            throw new Exception("Couldn't get private key. (" . openssl_error_string() . ")");
        }

        $this->keys[] = $res;

        return $res;
    }

    private function getRS256PublicKey() {
        if (!realpath($this->getPublic256KeyPath())) {
            $this->createRS256Certs();
        }

        $res = openssl_pkey_get_public("file://" . $this->getPublic256KeyPath());
        if (!$res) {
            throw new Exception("Couldn't get public key. (" . openssl_error_string() . ")");
        }

        $this->keys[] = $res;

        return $res;
    }

    private function createRS256Certs() {
        $config = [
            "digest_alg" => "RSA-SHA256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        $this->createCerts($config);
    }

    private function createCerts($config) {
        // Create key
        $res = openssl_pkey_new($config);

        if (!$res) {
            throw new Exception("Failed to generate new key: " . openssl_error_string());
        }

        $filesystem = new Filesystem();

        $filesystem->mkdir(static::CERT_DIR, 0770);

        $private = $this->getPrivate256KeyPath();
        $public = $this->getPublic256KeyPath();

        // Write private key file
        if (!openssl_pkey_export_to_file($res, $private)) {
            throw new Exception("Failed to export private key");
        }

        // Write public file //TODO do we need to check this worked?
        $filesystem->dumpFile($public, openssl_pkey_get_details($res)["key"]);

        // Free the resource
        openssl_pkey_free($res);
    }

    private function getPrivate256KeyPath() {
        return static::CERT_DIR . "testRS256.private.pem";
    }

    private function getPublic256KeyPath() {
        return static::CERT_DIR . "testRS256.public.pem";
    }

    protected function setUp(): void {
        if (!realpath($this->getPrivate256KeyPath())) {
            $this->createRS256Certs();
        }
    }

    protected function tearDown(): void {
        if ($this->keys) {
            foreach ($this->keys as $res) {
                openssl_pkey_free($res);
            }
        }
    }

}
