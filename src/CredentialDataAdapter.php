<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

interface CredentialDataAdapter
{
    public function fetch(?string $clue = null): ?CredentialData;
}
