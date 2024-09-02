<?php

declare(strict_types=1);

use Waglpz\Webapp\Security\Authenticator;
use Waglpz\Webapp\Security\AuthenticatorJWT;
use Waglpz\Webapp\Security\AuthStorage;
use Waglpz\Webapp\Security\AuthStorageInMemory;
use Waglpz\Webapp\Security\CredentialDataAdapter;
use Waglpz\Webapp\Security\CredentialDataAdapterJWT;
use Waglpz\Webapp\Security\CredentialDataDecoderInJWTUsingPubKeyDefault;
use Waglpz\Webapp\Security\Firewall;
use Waglpz\Webapp\Security\Firewalled;
use Waglpz\Webapp\Security\JWTDecoder;
use Waglpz\Webapp\Security\UserAuthRolesProvider;
use Waglpz\Webapp\Security\UserRolesProvider;

use function Waglpz\Config\config;

return [
    '*'                                                 => [
        'substitutions' => [
            JWTDecoder::class            => CredentialDataDecoderInJWTUsingPubKeyDefault::class,
            CredentialDataAdapter::class => CredentialDataAdapterJWT::class,
            Authenticator::class         => AuthenticatorJWT::class,
            AuthStorage::class           => '$DefaultAuthStorage',
            UserRolesProvider::class     => UserAuthRolesProvider::class,
            Firewalled::class            => Firewall::class,
        ],
    ],
    '$DefaultAuthStorage'                               => [
        'shared'          => true,
        'instanceOf'      => AuthStorageInMemory::class,
        'constructParams' => [
            [
                'roles'   => true,
                'spaces'  => true,
                'email'   => true,
                'id'      => true,
                'name'    => true,
                'picture' => true,
            ],
        ],
    ],
    Firewall::class                                     => [
        'shared'          => true,
        'constructParams' => [config('firewall')],
    ],
    CredentialDataDecoderInJWTUsingPubKeyDefault::class => [
        'shared'          => true,
        'constructParams' => [
            $_SERVER['JWT_PUBLIC_RSA_KEY_FILE'],
        ],
    ],
];
