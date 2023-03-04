<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

interface CredentialDataDecoder
{
    public function decode(mixed $data, string $clue): CredentialData|null;
}
