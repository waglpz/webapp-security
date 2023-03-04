<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Psr\Http\Message\ServerRequestInterface;

final class AuthenticatorBasic implements Authenticator
{
    private string|null $username;

    public function __construct(private readonly CredentialDataAdapter $authDataAdapter)
    {
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        $serverParams = $request->getServerParams();
        $username     = $serverParams['PHP_AUTH_USER'] ?? null;
        $password     = $serverParams['PHP_AUTH_PW'] ?? null;

        if (! isset($username, $password)) {
            return false;
        }

        $foundUserAuthData = $this->authDataAdapter->fetch($username);

        if ($foundUserAuthData === null) {
            return false;
        }

        if (\password_verify($password, $foundUserAuthData->passwordHash())) {
            $this->username = $username;

            return true;
        }

        return false;
    }

    public function username(): string|null
    {
        return $this->username ?? null;
    }
}
