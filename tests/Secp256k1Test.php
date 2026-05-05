<?php

namespace nostriphant\NIP01Tests;

use nostriphant\Secp256k1\Secp256k1;


it('generates a private key', function () {
    $private_key = Secp256k1::generate();
    expect($private_key)->toBeString();

    $public_key = Secp256k1::derive($private_key);
    expect($public_key)->toBe(substr((new \Elliptic\EC('secp256k1'))->keyFromPrivate($private_key)->getPublic(true, 'hex'), 2));
});

$vectors = json_decode(file_get_contents(__DIR__ . '/vectors/ecdh-secp256k1.json'), false);
it('works with paulmillrs vectors', function ($vector) {
    // https://github.com/paulmillr/noble-secp256k1/blob/main/test/wycheproof/ecdh_secp256k1_test.json
    
    $secret = Secp256k1::sharedSecret(substr($vector->public, 46))($vector->private);

    //$secret = Key::fromHex($vector->private)(Key::sharedSecret(substr($vector->public, 46)));
    expect(str_pad($secret, 64, '0', STR_PAD_LEFT))->toBe($vector->shared);
})->with(array_filter($vectors->testGroups[0]->tests, fn($vector) => $vector->result === 'valid'));

it('can sign a string and verify a signature', function () {
    $private_key = '435790f13406085d153b10bd9e00a9f977e637f10ce37db5ccfc5d3440c12d6c';

    expect(Secp256k1::derive($private_key))->toBe('89ac55aeeb301252da33b51ca4d189cb1d665b8f00618f5ea72c2ec59ca555e9');

    $hash = hash('sha256', 'hallo world');
    $signature = Secp256k1::sign($private_key, $hash);

    expect(Secp256k1::verify('89ac55aeeb301252da33b51ca4d189cb1d665b8f00618f5ea72c2ec59ca555e9', $hash, $signature))->toBeTrue();
});
