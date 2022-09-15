<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class CredentialDataAdapterInMemory implements CredentialDataAdapter
{
    /** @var array<array<string,string>> */
    private array $credentialData;

    /** @param array<array<string,string>> $credentialData */
    public function __construct(array $credentialData)
    {
        $this->credentialData = $credentialData;
    }

    public function fetch(?string $clue = null): ?CredentialData
    {
        $foundUsersData = \array_filter(
            $this->credentialData,
            static fn (array $userData): bool => isset($userData['username']) && $userData['username'] === $clue
        );

        if ($foundUsersData === []) {
            return null;
        }

        $foundUserData = \array_shift($foundUsersData);

        return new CredentialData($foundUserData);
    }
}
