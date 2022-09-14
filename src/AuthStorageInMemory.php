<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

/**
 * @property array<mixed> $roles
 * @property string $email
 * @property string $id
 * @property ?string $name    = null
 * @property ?string $picture = null
 */
final class AuthStorageInMemory implements AuthStorage
{
    /** @var array<string,mixed> */
    private array $storage;
    /** @var array<string,mixed> */
    private array $allowed;

    /**
     * @param mixed[] $allowed
     */
    public function __construct(?array $allowed = null)
    {
        $this->allowed = $allowed ?? [
            'roles' => true,
            'email' => true,
            'id' => true,
            'name' => true,
            'picture' => true,
        ];
    }

    /**
     * @inheritDoc
     */
    public function __get(string $name)
    {
        /** @phpstan-ignore-next-line */
        if (! isset($this->{$name})) {
            throw new \InvalidArgumentException(\sprintf('Auth storage does not have an value named "%s".', $name));
        }

        return $this->storage[$name];
    }

    /**
     * @inheritDoc
     */
    public function __set(string $name, $data): void
    {
        if (! isset($this->allowed[$name]) || $this->allowed[$name] !== true) {
            throw new \InvalidArgumentException(
                \sprintf('Auth storage does not allowed store value named "%s".', $name)
            );
        }

        /** @phpstan-ignore-next-line */
        if (isset($this->{$name})) {
            throw new \InvalidArgumentException(
                \sprintf('Auth storage does not allowed to override existing value named "%s".', $name)
            );
        }

        $this->storage[$name] = $data;
    }

    public function __isset(string $name): bool
    {
        return isset($this->storage[$name]);
    }

    /**
     * @inheritDoc
     */
    public function assign(array $data): void
    {
        foreach ($data as $name => $value) {
            /** @phpstan-ignore-next-line */
            $this->{$name} = $value;
        }
    }

    public function reset(): void
    {
        $this->storage = [];
    }

    public function hasSingleRolle(string $rolle): bool
    {
        return $this->hasRolle($rolle) && \count($this->roles) === 1;
    }

    public function hasRolle(string $rolle): bool
    {
        return \in_array($rolle, $this->roles, true);
    }
}
