<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

interface UserAuthDataAdapter
{
    public function fetchByUsername(string $username): ?UserAuthData;
}
