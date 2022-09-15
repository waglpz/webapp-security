<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class CredentialData
{
    private string $username;
    private string $passwordHash;
    /** @var array<int, string> */
    private array $roles;

    /** @param array<mixed> $authData */
    public function __construct(array $authData)
    {
        if (! isset($authData['username'], $authData['passwordHash'])) {
            throw new \InvalidArgumentException(
                'Invalid $authData expected an array with keys username and passwordHash and string as values.'
            );
        }

        if (! \is_string($authData['username']) || $authData['username'] === '') {
            throw new \InvalidArgumentException('Invalid $authData[\'username\'] given.');
        }

        $this->username = $authData['username'];

        if (\is_string($authData['role']) && $authData['role'] !== '') {
            $this->roles = [$authData['role']];
        } elseif (\is_array($authData['role']) && $authData['role'] !== []) {
            $this->roles = $authData['role'];
        } else {
            throw new \InvalidArgumentException('Invalid $authData[\'role\'] given.');
        }

        if (! \is_string($authData['passwordHash']) || $authData['passwordHash'] === '') {
            throw new \InvalidArgumentException('Invalid $authData[\'passwordHash\'] given.');
        }

        $this->passwordHash = $authData['passwordHash'];
    }

    public function username(): string
    {
        return $this->username;
    }

    /** @return array<int, string> */
    public function roles(): array
    {
        return $this->roles;
    }

    public function passwordHash(): string
    {
        return $this->passwordHash;
    }
}
