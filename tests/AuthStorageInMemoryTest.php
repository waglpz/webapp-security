<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\AuthStorageInMemory;

final class AuthStorageInMemoryTest extends TestCase
{
    /** @test */
    public function itReset(): void
    {
        $sut        = new AuthStorageInMemory();
        $sut->roles = ['role'];
        $sut->email = 'tester@email.akme.com';
        $sut->reset();
        self::assertFalse(isset($sut->email));
        self::assertFalse(isset($sut->roles));
    }

    /** @test */
    public function itAssign(): void
    {
        $sut  = new AuthStorageInMemory();
        $data = [
            'roles' => ['ROLE'],
            'email' => 'tester@akme.com',
        ];
        $sut->assign($data);
        self::assertSame('tester@akme.com', $sut->email);
        self::assertSame(['ROLE'], $sut->roles);
    }

    /** @test */
    public function itHasRole(): void
    {
        $sut  = new AuthStorageInMemory();
        $data = [
            'roles' => ['ROLE', 'ROLE_TEST', 'ROLE_Z'],
        ];
        $sut->assign($data);
        self::assertTrue($sut->hasRole('ROLE_TEST'));
        self::assertFalse($sut->hasRole('ROLE_WRONG'));
    }

    /** @test */
    public function itHasSingleRole(): void
    {
        $sut  = new AuthStorageInMemory();
        $data = [
            'roles' => ['ROLE', 'ROLE_TEST', 'ROLE_Z'],
        ];
        $sut->assign($data);
        self::assertFalse($sut->hasSingleRole('ROLE_Z'));

        $sut  = new AuthStorageInMemory();
        $data = [
            'roles' => ['ROLE_Z'],
        ];
        $sut->assign($data);
        self::assertTrue($sut->hasSingleRole('ROLE_Z'));
    }

    /** @test */
    public function itThrowsAnExceptionWhenTryToGetUnknownMember(): void
    {
        $sut = new AuthStorageInMemory();
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth storage does not have an value named "wrong".');
        /** @noinspection PhpUndefinedFieldInspection */
        $sut->wrong; /* @phpstan-ignore-line */
    }

    /** @test */
    public function itThrowsAnExceptionWhenTryToSetValueForNotAllowedName(): void
    {
        $sut = new AuthStorageInMemory();
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth storage does not allowed store value named "notAllowed".');
        /** @noinspection PhpUndefinedFieldInspection */
        $sut->notAllowed = 'some value'; /* @phpstan-ignore-line */
    }

    /** @test */
    public function itThrowsAnExceptionWhenTryToOverrideValueForGivenName(): void
    {
        $sut = new AuthStorageInMemory();
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Auth storage does not allowed to override existing value named "name".');
        /** @noinspection PhpUndefinedFieldInspection */
        /** @noinspection PhpFieldImmediatelyRewrittenInspection */
        $sut->name = 'some value';
        /** @noinspection PhpUndefinedFieldInspection */
        $sut->name = 'new value';
    }
}
