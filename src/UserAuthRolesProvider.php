<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class UserAuthRolesProvider implements UserRolesProvider
{
    private UserAuthDataAdapter $authDataAdapter;

    public function __construct(UserAuthDataAdapter $authDataAdapter)
    {
        $this->authDataAdapter = $authDataAdapter;
    }

    /** @inheritDoc */
    public function findRole(?string $username): array
    {
        if (! isset($username)) {
            return [Role::ROLE_NOT_AUTHENTICATED];
        }

        $foundUserAuthData = $this->authDataAdapter->fetchByUsername($username);

        if ($foundUserAuthData === null) {
            return [Role::ROLE_NOT_AUTHENTICATED];
        }

        return $foundUserAuthData->roles();
    }
}
