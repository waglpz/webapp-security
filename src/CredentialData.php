<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class CredentialData
{
    private string $username;
    private string $passwordHash;
    /** @var array<int, string> */
    private array $spaces;
    /** @var array<int, string> */
    private array $roles;

    /**
     * @param array<int, string>|string $roles
     * @param array<int, string>|string $spaces
     */
    public function __construct(
        string $emailOrUsername,
        array|string $roles = [],
        array|string $spaces = [],
        string|null $passwordHash = null,
    ) {
        if ($emailOrUsername === '') {
            throw new \InvalidArgumentException(
                'Invalid $emailOrUsername, expected not empty string.',
            );
        }

        $this->username = $emailOrUsername;

        if (\is_string($roles)) {
            $this->roles = $roles === '' ? [] : [$roles];
        } else {
            $this->roles = $roles;
        }

        if (\is_string($spaces)) {
            $this->spaces = $spaces === '' ? [] : [$spaces];
        } else {
            $this->spaces = $spaces;
        }

        $this->passwordHash = $passwordHash ?? '';
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

    /** @return array<int, string> */
    public function spaces(): array
    {
        return $this->spaces;
    }

    public function passwordHash(): string
    {
        return $this->passwordHash;
    }
}
