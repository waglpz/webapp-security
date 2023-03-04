<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataAdapterInMemory;
use Waglpz\Webapp\Security\CredentialDataDecoder;

final class CredentialDataAdapterInMemoryTest extends TestCase
{
    /** @test */
    public function itReturnsNullIfClueEmpty(): void
    {
        $inMemoryData = [];
        $dataDecoder  = $this->createMock(CredentialDataDecoder::class);
        $dataDecoder->expects(self::never())->method('decode');
        $sut  = new CredentialDataAdapterInMemory($inMemoryData, $dataDecoder);
        $fact = $sut->fetch('');
        self::assertNull($fact);
        $fact = $sut->fetch();
        self::assertNull($fact);
    }

    /** @test */
    public function itReturnsClueEmpty(): void
    {
        $credentialData = new CredentialData('tester');
        $inMemoryData   = [['username' => 'tester'], ['username' => 'tester_1']];
        $dataDecoder    = $this->createMock(CredentialDataDecoder::class);

        $dataDecoder->expects(self::once())
                    ->method('decode')
                    ->with($inMemoryData, 'tester')
                    ->willReturn($credentialData);

        $sut  = new CredentialDataAdapterInMemory($inMemoryData, $dataDecoder);
        $fact = $sut->fetch('tester');
        self::assertInstanceOf(CredentialData::class, $fact);
        self::assertSame('tester', $fact->username());
    }
}
