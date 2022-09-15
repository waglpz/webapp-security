<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Ahc\Jwt\JWT;
use Psr\Http\Message\ServerRequestInterface;

final class CredentialDataAdapterJWT implements CredentialDataAdapter
{
    private JWT $JWTokenizer;
    private ServerRequestInterface $request;

    public function __construct(JWT $JWTokenizer, ServerRequestInterface $request)
    {
        $this->JWTokenizer = $JWTokenizer;
        $this->request     = $request;
    }

    public function fetch(?string $clue = null): ?CredentialData
    {
        $authorizationHeader      = $this->request->getHeaderLine('Authorization');
        $authorizationHeaderArray = \explode(' ', $authorizationHeader);
        $token                    = $authorizationHeaderArray[1] ?? null;

        if ($token === null) {
            return null;
        }

        try {
            $payload = $this->JWTokenizer->decode($token);
        } catch (\Throwable $exception) {
            return null;
        }

        if ($payload === []) {
            return null;
        }

        if (! isset($payload['username'])) {
            return null;
        }

        if (! isset($payload['role'])) {
            return null;
        }

        $payload['passwordHash'] = 'passwordHashDoesNotUsed';

        return new CredentialData($payload);
    }
}
