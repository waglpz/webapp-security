<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\AuthenticatorJWT;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataAdapterJWT;
use Waglpz\Webapp\Security\JWTDecoder;

final class AuthenticatorJWTTest extends TestCase
{
    /** @test */
    public function itAuthenticates(): void
    {
        $header  = 'Bearer a.b.c';
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getHeaderLine')
                ->with('Authorization')
                ->willReturn($header);

        $result     = new CredentialData('tester');
        $JWTDecoder = $this->createMock(JWTDecoder::class);
        $JWTDecoder->expects(self::once())->method('decode')->willReturn($result);

        $credAdapter = new CredentialDataAdapterJWT($request, $JWTDecoder);
        $sut         = new AuthenticatorJWT($credAdapter);
        $fact        = $sut->authenticate($request);
        self::assertTrue($fact);
        self::assertSame('tester', $sut->username());
    }

    /** @test */
    public function itDoesNotAuthenticate(): void
    {
        $header  = '';
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getHeaderLine')
                ->with('Authorization')
                ->willReturn($header);

        $JWTDecoder = $this->createMock(JWTDecoder::class);
        $JWTDecoder->expects(self::never())->method('decode');

        $credAdapter = new CredentialDataAdapterJWT($request, $JWTDecoder);
        $sut         = new AuthenticatorJWT($credAdapter);
        $fact        = $sut->authenticate($request);
        self::assertFalse($fact);
    }

    /** @test */
    public function itDoesNotAuthenticate2(): void
    {
        $header  = 'Bearer a.b.c';
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getHeaderLine')
                ->with('Authorization')
                ->willReturn($header);

        $JWTDecoder = $this->createMock(JWTDecoder::class);
        $JWTDecoder->expects(self::once())->method('decode')->willReturn(null);

        $credAdapter = new CredentialDataAdapterJWT($request, $JWTDecoder);
        $sut         = new AuthenticatorJWT($credAdapter);
        $fact        = $sut->authenticate($request);
        self::assertFalse($fact);
    }
}
