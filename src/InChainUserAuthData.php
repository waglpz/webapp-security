<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class InChainUserAuthData implements UserAuthDataAdapter
{
    /** @var UserAuthDataAdapter[] */
    private array $userAuthDataAdapter;

    /** @param array<UserAuthDataAdapter> $userAuthDataAdapter */
    public function __construct(array $userAuthDataAdapter)
    {
        $this->userAuthDataAdapter = $userAuthDataAdapter;
    }

    public function fetchByUsername(string $username): ?UserAuthData
    {
        foreach ($this->userAuthDataAdapter as $adapter) {
            $fetchedData = $adapter->fetchByUsername($username);

            if ($fetchedData !== null) {
                return $fetchedData;
            }
        }

        return null;
    }
}
