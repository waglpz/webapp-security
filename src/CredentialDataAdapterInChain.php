<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class CredentialDataAdapterInChain implements CredentialDataAdapter
{
    /** @var CredentialDataAdapter[] */
    private array $credentialDataAdapters;

    /** @param array<CredentialDataAdapter> $credentialDataAdapters */
    public function __construct(array $credentialDataAdapters)
    {
        $this->credentialDataAdapters = $credentialDataAdapters;
    }

    public function fetch(?string $clue = null): ?CredentialData
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
