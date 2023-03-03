<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use InvalidArgumentException;

/**
 * @property array<int,string> $roles
 * @property string       $email
 * @property string       $id
 * @property ?string      $name    = null
 * @property ?string      $picture = null
 */
final class AuthStoragePHPSession extends \stdClass implements AuthStorage
{
    public function __get(string $name): mixed
    {
        if ($this->__isset($name)) {
            return $_SESSION['auth_storage'][$name];
        }

        // return a default role unless roles wasn't set
        if ($name === 'roles') {
            return [Role::ROLE_NOT_AUTHENTICATED];
        }

        if ($name === 'picture' || $name === 'name') {
            return null;
        }

        if ($name === 'email') {
            $message = 'Invalid email address or unauthorized user.';
        } elseif ($name === 'id') {
            $message = 'Invalid user ID or unauthorized user.';
        } else {
            $message = 'Invalid key given "' . $name . '".';
        }

        throw new InvalidArgumentException($message);
    }

    public function __set(string $name, mixed $data): void
    {
        /** @noinspection NotOptimalIfConditionsInspection */
        if ($this->__isset($name) && $_SESSION['auth_storage'][$name] !== $data) {
            throw new InvalidArgumentException('Auth storage already initialized with attribute "' . $name . '".');
        }

        $_SESSION['auth_storage'][$name] = $data;
    }

    public function __isset(string $name): bool
    {
        return isset($this->$name) || isset($_SESSION['auth_storage'][$name]);
    }

    /** @param array<string,mixed> $data */
    public function assign(array $data): void
    {
        foreach ($data as $name => $value) {
            $this->__set($name, $value);
        }
    }

    public function reset(): void
    {
        $_SESSION['auth_storage'] = null;
    }

    public function hasSingleRole(string $role): bool
    {
        return $this->hasRole($role) && \count($this->roles) === 1;
    }

    public function hasRole(string $role): bool
    {
        return \in_array($role, $this->roles, true);
    }
}
