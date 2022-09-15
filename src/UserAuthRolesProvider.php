<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class UserAuthRolesProvider implements UserRolesProvider
{
    private CredentialDataAdapter $credentialDataAdapter;

    public function __construct(CredentialDataAdapter $credentialDataAdapter)
    {
        $this->credentialDataAdapter = $credentialDataAdapter;
    }

    /** @inheritDoc */
    public function findRole(?string $username): array
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
