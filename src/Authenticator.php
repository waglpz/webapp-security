<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Psr\Http\Message\ServerRequestInterface;

interface Authenticator
{
    public function authenticate(ServerRequestInterface $request): bool;

    public function username(): ?string;
}
