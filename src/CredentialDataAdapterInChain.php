<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class CredentialDataAdapterInChain implements CredentialDataAdapter
{
    /** @param array<CredentialDataAdapter> $credentialDataAdapters */
    public function __construct(private readonly array $credentialDataAdapters)
    {
    }

    public function fetch(string|null $clue = null): CredentialData|null
    {
        foreach ($this->credentialDataAdapters as $adapter) {
            $fetchedData = $adapter->fetch($clue);

            if ($fetchedData !== null) {
                return $fetchedData;
            }
        }

        return null;
    }
}
