<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

interface JWTDecoder
{
    public function decode(string $token): CredentialData|null;
}
