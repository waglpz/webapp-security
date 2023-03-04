<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

final class CredentialDataAdapterInMemory implements CredentialDataAdapter
{
    /** @param array<array<string,string>> $inMemoryData */
    public function __construct(private array $inMemoryData, private CredentialDataDecoder $dataDecoder)
    {
    }

    public function fetch(string|null $clue = null): CredentialData|null
    {
        if ($clue === null || $clue === '') {
            return null;
        }

        return $this->dataDecoder->decode($this->inMemoryData, $clue);
    }
}
