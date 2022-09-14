<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Ahc\Jwt\JWT;
use Psr\Http\Message\ServerRequestInterface;

final class JWTAuthenticator implements Authenticator
{
    private AuthStorage $authStorage;
    private ?string $username;
    private JWT $jwtVerifier;

    public function __construct(AuthStorage $authStorage, JWT $jwtVerifier)
    {
        $this->authStorage = $authStorage;
        $this->jwtVerifier = $jwtVerifier;
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        $authorizationHeader      = $request->getHeaderLine('Authorization');
        $authorizationHeaderArray = \explode(' ', $authorizationHeader);
        $token                    = $authorizationHeaderArray[1] ?? null;

        if ($token === null) {
            return false;
        }

        try {
            $jwtPayload = $this->jwtVerifier->decode($token);
        } catch (\Throwable $exception) {
            return false;
        }

        if (! isset($jwtPayload['userdata'])) {
            return false;
        }

        try {
            $this->authStorage->assign($jwtPayload['userdata']);
            $this->username = $this->authStorage->email;

            return true;
        } catch (\Throwable $exception) {
            return false;
        }
    }

    public function username(): ?string
    {
        return $this->username;
    }
}
