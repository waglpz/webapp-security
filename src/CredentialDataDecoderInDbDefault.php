<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class CredentialDataDecoderInDbDefault implements CredentialDataDecoder
{
    public function decode(mixed $data, string $clue): CredentialData|null
    {
        if (! $data instanceof \stdClass || $clue === '') {
            return null;
        }

        if (! isset($data->username) || \strcasecmp((string) $data->username, $clue) !== 0) {
            return null;
        }

        $role         = $data->role ?? [];
        $spaces       = $data->spaces ?? [];
        $passwordHash = $data->passwordHash ?? null;

        return new CredentialData($data->username, $role, $spaces, $passwordHash);
    }
}
