<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataAdapter;
use Waglpz\Webapp\Security\Role;
use Waglpz\Webapp\Security\UserAuthRolesProvider;

final class UserAuthRolesProviderTest extends TestCase
{
    /** @test */
    public function itReturnsRoles(): void
    {
        $credAdapter = $this->createMock(CredentialDataAdapter::class);
        $roles       = ['ROLE_A'];
        $credData    = new CredentialData('tester', $roles, '', '');
        $credAdapter->expects(self::once())->method('fetch')->willReturn($credData);
        $fact = (new UserAuthRolesProvider($credAdapter))->findRole('tester');
        self::assertSame(['ROLE_A'], $fact);
    }

    /** @test */
    public function itReturnsRoleNotAuthenticated(): void
    {
        $credAdapter = $this->createMock(CredentialDataAdapter::class);
        $credData    = new CredentialData('tester', '', '', '');
        $credAdapter->expects(self::never())->method('fetch')->willReturn($credData);
        $fact = (new UserAuthRolesProvider($credAdapter))->findRole(null);
        self::assertSame([Role::ROLE_NOT_AUTHENTICATED], $fact);

        $credAdapter = $this->createMock(CredentialDataAdapter::class);
        $credData    = null;
        $credAdapter->expects(self::once())->method('fetch')->willReturn($credData);
        $fact = (new UserAuthRolesProvider($credAdapter))->findRole('tester');
        self::assertSame([Role::ROLE_NOT_AUTHENTICATED], $fact);
    }
}
