<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

final class CredentialDataDecoderInJWTUsingPubKeyDefault implements JWTDecoder
{
    private string $publicKeyFile;

    public function __construct(string $publicKeyFile, private readonly string $algo = 'RS256')
    {
        if (! \is_file($publicKeyFile) || ! \is_readable($publicKeyFile)) {
            throw new \InvalidArgumentException('Public KEY file does not exist or not readable.');
        }

        $fileContent = \file_get_contents($publicKeyFile);
        \assert(\is_string($fileContent));
        $this->publicKeyFile = $fileContent;
    }

    public function decode(mixed $token): CredentialData|null
    {
        if (! \is_string($token) || $token === '') {
            return null;
        }

        $key = new Key($this->publicKeyFile, $this->algo);

        $data = JWT::decode($token, $key);

        if (! isset($data->userData)) {
            return null;
        }

        $userData = $data->userData;

        if (! isset($userData->email)) {
            return null;
        }

        $roles        = $userData->roles ?? [];
        $spaces       = $userData->spaces ?? [];
        $passwordHash = $userData->passwordHash ?? null;

        return new CredentialData($userData->email, $roles, $spaces, $passwordHash);
    }
}
