<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\AuthenticatorBasic;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataAdapter;

final class AuthenticatorBasicTest extends TestCase
{
    /** @test */
    public function itAuthenticates(): void
    {
        $result = new CredentialData(
            'tester',
            [],
            [],
            '$argon2id$v=19$m=65536,t=4,p=1$U3ZNMi9PbkVaMGpHQlFORg$EPnNgD2ROyLHQsJoZprDmjsonMcFaBZlsC+9/rdxhgM',
        );

        $credDataAdapter = $this->createMock(CredentialDataAdapter::class);
        $credDataAdapter->expects(self::once())->method('fetch')->willReturn($result);
        $sut = new AuthenticatorBasic($credDataAdapter);

        $serverParams = [
            'PHP_AUTH_USER' => 'tester',
            'PHP_AUTH_PW'   => 'passwd',
        ];
        $request      = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getServerParams')
                ->willReturn($serverParams);

        $fact = $sut->authenticate($request);
        self::assertTrue($fact);
        self::assertSame('tester', $sut->username());
    }

    /** @test */
    public function itDoesNotAuthenticates1(): void
    {
        $credDataAdapter = $this->createMock(CredentialDataAdapter::class);
        $credDataAdapter->expects(self::never())->method('fetch');
        $sut = new AuthenticatorBasic($credDataAdapter);

        $serverParams = null;
        $request      = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getServerParams')
                ->willReturn($serverParams);

        $fact = $sut->authenticate($request);
        self::assertFalse($fact);
        self::assertNull($sut->username());
    }

    /** @test */
    public function itDoesNotAuthenticates2(): void
    {
        $result = null;

        $credDataAdapter = $this->createMock(CredentialDataAdapter::class);
        $credDataAdapter->expects(self::once())->method('fetch')->willReturn($result);
        $sut = new AuthenticatorBasic($credDataAdapter);

        $serverParams = [
            'PHP_AUTH_USER' => 'tester',
            'PHP_AUTH_PW'   => 'passwd',
        ];
        $request      = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getServerParams')
                ->willReturn($serverParams);

        $fact = $sut->authenticate($request);
        self::assertFalse($fact);
        self::assertNull($sut->username());
    }

    /** @test */
    public function itDoesNotAuthenticates3(): void
    {
        $result = new CredentialData(
            'tester',
            [],
            [],
            '$argon2id$v=19$m=65536,t=4,p=1$U3ZNMi9PbkVaMGpHQlFORg$EPnNgD2ROyLHQsJoZprDmjsonMcFaBZlsC+9/rdxhgM',
        );

        $credDataAdapter = $this->createMock(CredentialDataAdapter::class);
        $credDataAdapter->expects(self::once())->method('fetch')->willReturn($result);
        $sut = new AuthenticatorBasic($credDataAdapter);

        $serverParams = [
            'PHP_AUTH_USER' => 'tester',
            'PHP_AUTH_PW'   => 'wrong',
        ];
        $request      = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getServerParams')
                ->willReturn($serverParams);

        $fact = $sut->authenticate($request);
        self::assertFalse($fact);
        self::assertNull($sut->username());
    }
}
