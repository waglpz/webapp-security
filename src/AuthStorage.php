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
    /**
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    public function __get(string $name);

    /**
     * @param mixed $data
     *
     * @throws \InvalidArgumentException
     */
    public function __set(string $name, $data): void;

    public function __isset(string $name): bool;

    /** @param array<string,mixed> $data */
    public function assign(array $data): void;

    public function reset(): void;

    public function hasSingleRolle(string $rolle): bool;

    public function hasRolle(string $rolle): bool;
}
