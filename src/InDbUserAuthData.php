<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use PDO;

final class InDbUserAuthData implements UserAuthDataAdapter
{
    private PDO $pdo;
    private string $lookUpStatement;

    /** @param array<mixed>|null $options */
    public function __construct(PDO $pdo, ?array $options = null)
    {
        if (! isset($options['in-db-look-up-stmt'])) {
            $this->lookUpStatement = <<<SQL
SELECT `username`, `passwordHash`, `role` 
FROM api_login 
WHERE username = :username 
  AND timeExpired >= :currentTime; 
SQL;
        } else {
            \assert(\is_string($options['in-db-look-up-stmt']));
            $this->lookUpStatement = $options['in-db-look-up-stmt'];
        }

        $this->pdo = $pdo;
    }

    public function fetchByUsername(string $username): ?UserAuthData
    {
        $params = [
            'username' => $username,
            'currentTime' => \date('Y-m-d H:i:s'),
        ];

        $sth = $this->pdo->prepare($this->lookUpStatement);
        $sth->execute($params);
        $foundUserData = $sth->fetch(PDO::FETCH_ASSOC);

        if (
            \is_array($foundUserData)
            && isset($foundUserData['username'], $foundUserData['passwordHash'], $foundUserData['role'])
            && \strcasecmp((string) $foundUserData['username'], $username) === 0
        ) {
            return new UserAuthData($foundUserData);
        }

        return null;
    }
}
