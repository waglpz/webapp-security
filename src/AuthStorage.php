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
interface AuthStorage
{
    /** @throws \InvalidArgumentException */
    public function __get(string $name): mixed;

    /** @throws \InvalidArgumentException */
    public function __set(string $name, mixed $data): void;

    public function __isset(string $name): bool;

    /** @param array<string,mixed> $data */
    public function assign(array $data): void;

    public function reset(): void;

    public function hasSingleRole(string $role): bool;

    public function hasRole(string $role): bool;
}
