<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use PDO;

final class CredentialDataAdapterInDb implements CredentialDataAdapter
{
    private string $lookUpStatement;

    /** @param array<mixed>|null $options */
    public function __construct(
        private readonly PDO $pdo,
        private readonly CredentialDataDecoder $dataDecoder,
        array|null $options = null,
    ) {
        if (! isset($options['in-db-look-up-stmt'])) {
            $this->lookUpStatement = <<<'SQL'
SELECT `username`, `passwordHash`, `role` 
FROM api_login 
WHERE username = :username 
  AND timeExpired >= :currentTime
SQL;
        } else {
            \assert(\is_string($options['in-db-look-up-stmt']));
            $this->lookUpStatement = $options['in-db-look-up-stmt'];
        }
    }

    public function fetch(string|null $clue = null): CredentialData|null
    {
        if ($clue === null || $clue === '') {
            return null;
        }

        $params = [
            'username'    => $clue,
            'currentTime' => \date('Y-m-d H:i:s'),
        ];

        $sth = $this->pdo->prepare($this->lookUpStatement);
        $sth->execute($params);
        $foundUserData = $sth->fetch(PDO::FETCH_OBJ);

        return $this->dataDecoder->decode($foundUserData, $clue);
    }
}
