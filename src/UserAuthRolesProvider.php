<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class UserAuthRolesProvider implements UserRolesProvider
{
    public function __construct(private readonly CredentialDataAdapter $credentialDataAdapter)
    {
    }

    /** @inheritDoc */
    public function findRole(string|null $username): array
    {
        if (! isset($username)) {
            return [Role::ROLE_NOT_AUTHENTICATED];
        }

        $credentialData = $this->credentialDataAdapter->fetch($username);

        if ($credentialData === null) {
            return [Role::ROLE_NOT_AUTHENTICATED];
        }

        return $credentialData->roles();
    }
}
