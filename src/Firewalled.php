<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Psr\Http\Message\ServerRequestInterface;

interface Firewalled
{
    /** @param array<mixed> $currentRoles */
    public function checkRules(ServerRequestInterface $request, array $currentRoles): void;
}
