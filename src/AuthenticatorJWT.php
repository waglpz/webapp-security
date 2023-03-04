<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Psr\Http\Message\ServerRequestInterface;

final class AuthenticatorJWT implements Authenticator
{
    private string|null $username;

    public function __construct(private readonly CredentialDataAdapterJWT $credentialDataAdapter)
    {
    }

    public function authenticate(ServerRequestInterface $request): bool
    {
        $authData = $this->credentialDataAdapter->fetch(/* data from JWT */);

        if ($authData === null) {
            return false;
        }

        $this->username = $authData->username();

        return true;
    }

    public function username(): string|null
    {
        return $this->username;
    }
}
