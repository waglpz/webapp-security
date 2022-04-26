<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

interface UserRolesProvider
{
    /** @return array<mixed> */
    public function findRole(string $username): array;
}
