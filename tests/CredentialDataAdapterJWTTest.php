<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataAdapterJWT;
use Waglpz\Webapp\Security\JWTDecoder;

final class CredentialDataAdapterJWTTest extends TestCase
{
    /** @test */
    public function itsCanCredentialDataFromJWT(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getHeaderLine')
                ->with('Authorization')
                ->willReturn('Bearer abc');
        $JWTDecoder = $this->createMock(JWTDecoder::class);
        $JWTDecoder->expects(self::once())
                   ->method('decode')
                   ->with('abc')
                   ->willReturn((new CredentialData('tester')));

        $sut  = new CredentialDataAdapterJWT($request, $JWTDecoder);
        $fact = $sut->fetch('tester');
        self::assertInstanceOf(CredentialData::class, $fact);
        self::assertSame('tester', $fact->username());
        self::assertSame([], $fact->roles());
        self::assertSame([], $fact->spaces());
        self::assertSame('', $fact->passwordHash());
    }

    /** @test */
    public function itsCanNotCredentialDataFromJWTIfJWTWasNotInHeader(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())
                ->method('getHeaderLine')
                ->with('Authorization')
                ->willReturn('Bearer ');
        $JWTDecoder = $this->createMock(JWTDecoder::class);
        $JWTDecoder->expects(self::never())->method('decode');

        $sut  = new CredentialDataAdapterJWT($request, $JWTDecoder);
        $fact = $sut->fetch('tester');
        self::assertNull($fact);
    }

    /** @test */
    public function itsCanNotCredentialDataFromJWTIfJWTDecodeThrowsException(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())->method('getHeaderLine')->willReturn('Bearer XAB123.23213.122');
        $JWTDecoder = $this->createMock(JWTDecoder::class);
        $ex         = $this->createMock(\Throwable::class);
        $JWTDecoder->expects(self::once())->method('decode')->willThrowException($ex);

        $sut  = new CredentialDataAdapterJWT($request, $JWTDecoder);
        $fact = $sut->fetch('tester');
        self::assertNull($fact);
    }
}
