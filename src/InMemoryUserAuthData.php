<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class InMemoryUserAuthData implements UserAuthDataAdapter
{
    /** @var array<array<string,string>> */
    private array $authData;

    /** @param array<array<string,string>> $authData */
    public function __construct(array $authData)
    {
        $this->authData = $authData;
    }

    public function fetchByUsername(string $username): ?UserAuthData
    {
        $foundUsersData = \array_filter(
            $this->authData,
            static fn (array $userData): bool => isset($userData['username']) && $userData['username'] === $username
        );

        if ($foundUsersData === []) {
            return null;
        }

        $foundUserData = \array_shift($foundUsersData);

        return new UserAuthData($foundUserData);
    }
}
