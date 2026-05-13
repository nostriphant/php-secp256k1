<?php


namespace nostriphant\Secp256k1;

use Elliptic\EC;

class Secp256k1 {
    static function curve(): EC {
        return new EC('secp256k1');
    }
    
    static function generate() : string {
        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'secp256k1'
        ];
        $keypair = openssl_pkey_new($config);
        $details = openssl_pkey_get_details($keypair);
        return implode(unpack("H*", $details['ec']['d']));
    }
    
    static function derive(string $private_key): string
    {
        if (function_exists('secp256k1_nostr_derive_pubkey')) {
            return secp256k1_nostr_derive_pubkey($private_key);
        }
        $curved_private_key = \EllipticCurve\PrivateKey::fromString($private_key);
        return substr($curved_private_key->publicKey()->toCompressed(), 2);
    }

    static function derToAsn(string $der): string {
        $hex = bin2hex($der);
        if (substr($hex, 0, 2) !== '30') {
            throw new \InvalidArgumentException("Ongeldig DER formaat.");
        }

        // Snijd de DER-wrapper op basis van byteseriatie uit
        $offset = 4;

        // Haal R op
        if (substr($hex, $offset, 2) !== '02') return '';
        $r_len = hexdec(substr($hex, $offset + 2, 2)) * 2;
        $r = substr($hex, $offset + 4, $r_len);
        if (strlen($r) > 64 && substr($r, 0, 2) === '00') { $r = substr($r, 2); } // Verwijder padding byte
        $r = str_pad($r, 64, '0', STR_PAD_LEFT);

        $offset += 4 + $r_len;

        // Haal S op
        if (substr($hex, $offset, 2) !== '02') return '';
        $s_len = hexdec(substr($hex, $offset + 2, 2)) * 2;
        $s = substr($hex, $offset + 4, $s_len);
        if (strlen($s) > 64 && substr($s, 0, 2) === '00') { $s = substr($s, 2); } // Verwijder padding byte
        $s = str_pad($s, 64, '0', STR_PAD_LEFT);

        return $r . $s;
    }

    static function sign(string $private_key, string $hash): string
    {
        if (function_exists('secp256k1_nostr_sign')) {
            return secp256k1_nostr_sign($private_key, $hash);
        }
        
        $curved_private_key = \EllipticCurve\PrivateKey::fromString($private_key);
        
        $signature_der = "";
        if (openssl_sign($hash, $signature_der, $curved_private_key->toPem(), OPENSSL_ALGO_SHA256) === false) {
            throw new \Exception('Failed signing: ' . openssl_error_string());
        }
        return self::derToAsn($signature_der);
    }

    static function verify(string $public_key, string $hash, string $signature): bool
    {
        if (function_exists('secp256k1_nostr_verify')) {
            return secp256k1_nostr_verify($public_key, $hash, $signature);
        }
        $curver_public_key = \EllipticCurve\PublicKey::fromCompressed('03'.$public_key);
        $signatureBinary = hex2bin($signature);
        return openssl_verify($hash, $signatureBinary, $curver_public_key->toPem(), OPENSSL_ALGO_SHA256);
    }

    static function sharedSecret(#[\SensitiveParameter] string $recipient_pubkey) {
        return function (#[\SensitiveParameter] string $private_key) use ($recipient_pubkey): bool|string {
            $ec = self::curve();
            try {
                $key1 = $ec->keyFromPrivate($private_key, 'hex');
                $pub2 = $ec->keyFromPublic($recipient_pubkey, 'hex')->pub;
                return $key1->derive($pub2)->toString('hex');
            } catch (\Exception $e) {
                throw new \InvalidArgumentException($e->getMessage());
            }
        };
    }
}
