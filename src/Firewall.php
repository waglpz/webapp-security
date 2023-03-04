<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Psr\Http\Message\ServerRequestInterface;

final class Firewall implements Firewalled
{
    /**
     * @param array<string,array<string>> $rules The key is regex pattern of the route and value as list of
     *                                            allowed roles
     */
    public function __construct(private array $rules)
    {
    }

    /**
     * @throws Forbidden
     *
     * @inheritDoc
     */
    public function checkRules(ServerRequestInterface $request, array $currentRoles): void
    {
        $uri = $request->getRequestTarget();

        \Waglpz\Webapp\Security\sortLongestKeyFirst($this->rules);

        foreach ($this->rules as $routePattern => $rollenAllowed) {
            if ($uri === '/') {
                return;
            }

            if ($routePattern === '/') {
                continue;
            }

            $prefix = $_SESSION['hash_uri'][$uri] ?? '';

            if (\preg_match('#^' . $prefix . $routePattern . '#', $uri) === 1) {
                if ($rollenAllowed === [Role::ROLE_NOT_AUTHENTICATED]) {
                    return;
                }

                $matchedRoles = \array_intersect($rollenAllowed, $currentRoles);
                if (\count($matchedRoles) >= 1) {
                    return;
                }

                throw new Forbidden();
            }
        }

        throw new Forbidden();
    }
}
