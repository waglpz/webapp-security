<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class CredentialDataDecoderInMemoryDefault implements CredentialDataDecoder
{
    public function decode(mixed $data, string $clue): CredentialData|null
    {
        if (! \is_array($data) || $data === [] || $clue === '') {
            return null;
        }

        $foundUsersData = \array_filter(
            $data,
            static fn ($userData): bool => \is_array($userData)
                && isset($userData['username'])
                && $userData['username'] === $clue
        );

        if ($foundUsersData === []) {
            return null;
        }

        $foundUserData = \array_shift($foundUsersData);
        $role          = $foundUserData['roles'] ?? [];
        $spaces        = $foundUserData['spaces'] ?? [];
        $passwordHash  = $foundUserData['passwordHash'] ?? null;

        return new CredentialData($foundUserData['username'], $role, $spaces, $passwordHash);
    }
}
