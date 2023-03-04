<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Psr\Http\Message\ServerRequestInterface;

final class CredentialDataAdapterJWT implements CredentialDataAdapter
{
    public function __construct(
        private readonly ServerRequestInterface $request,
        private readonly JWTDecoder $JWTDecoder,
    ) {
    }

    public function fetch(string|null $clue = null): CredentialData|null
    {
        $authorizationHeader      = $this->request->getHeaderLine('Authorization');
        $authorizationHeaderArray = \explode(' ', $authorizationHeader);
        $jwt                      = $authorizationHeaderArray[1] ?? null;

        if ($jwt === null || $jwt === '') {
            return null;
        }

        try {
            return $this->JWTDecoder->decode($jwt);
        } catch (\Throwable) {
            return null;
        }
    }
}
