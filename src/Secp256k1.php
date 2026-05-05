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
        $ec = self::curve();
        return substr($ec->keyFromPrivate($private_key)->getPublic(true, 'hex'), 2);
    }


    static function sign(string $private_key, string $hash): string
    {
        if (function_exists('secp256k1_nostr_sign')) {
            return secp256k1_nostr_sign($private_key, $hash);
        }
        $ec = self::curve();
        $key = $ec->keyFromPrivate($private_key, 'hex');
        return $key->sign($hash)->toDER('hex');
    }


    static function verify(string $public_key, string $hash, string $signature): bool
    {
        if (function_exists('secp256k1_nostr_verify')) {
            return secp256k1_nostr_verify($public_key, $hash, $signature);
        }
        $ec = self::curve();
        $key = $ec->keyFromPublic('03' . $public_key, 'hex');
        return $key->verify($hash, $signature);
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
