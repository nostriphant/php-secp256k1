FROM php:8.4

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

RUN ["apt", "update"]
RUN ["apt", "install", "-y", "libgmp-dev", "libsodium-dev", "autoconf", "libsecp256k1-dev", "build-essential", "git", "libtool", "pkgconf"]

RUN ["docker-php-ext-install", "gmp"]

RUN ["rm", "-rf", "/tmp/pear"]
RUN ["docker-php-ext-enable", "sodium"]

WORKDIR "/opt"
RUN ["git", "clone", "https://github.com/1ma/secp256k1-nostr-php"]
WORKDIR "/opt/secp256k1-nostr-php"
RUN ["make", "ext"]
#RUN ["apt", "install", "-y", "valgrind"]
#RUN ["make", "check"]
RUN ["make", "install"]
ADD ["./docker/ext-secp256k1-nostr-php.ini", "$PHP_INI_DIR/conf.d/ext-secp256k1-nostr-php.ini"]
