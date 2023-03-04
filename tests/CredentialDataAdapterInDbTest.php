<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PDO;
use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataAdapterInDb;
use Waglpz\Webapp\Security\CredentialDataDecoder;

final class CredentialDataAdapterInDbTest extends TestCase
{
    /** @test */
    public function itDoesFetchNothing(): void
    {
        $pdo = $this->createMock(PDO::class);
        $pdo->expects(self::never())->method('prepare');

        $dataDecoder = $this->createMock(CredentialDataDecoder::class);
        $dataDecoder->expects(self::never())->method('decode');

        $sut  = new CredentialDataAdapterInDb($pdo, $dataDecoder);
        $fact = $sut->fetch('');
        self::assertNull($fact);
        $fact = $sut->fetch();
        self::assertNull($fact);
    }

    /** @test */
    public function itFetches(): void
    {
        $foundUserData  = new \stdClass();
        $clue           = 'tester';
        $credentialData = new CredentialData('tester');
        $params         = [
            'username'    => 'tester',
            'currentTime' => \date('Y-m-d H:i:s'),
        ];

        $pdo = $this->createMock(PDO::class);
        $sth = $this->createMock(\PDOStatement::class);
        $sth->expects(self::once())->method('execute')->with($params);
        $sth->expects(self::once())
            ->method('fetch')
            ->with(PDO::FETCH_OBJ)
            ->willReturn($foundUserData);
        $pdo->expects(self::once())
            ->method('prepare')
            ->with(self::isType('string'))
            ->willReturn($sth);

        $dataDecoder = $this->createMock(CredentialDataDecoder::class);
        $dataDecoder->expects(self::once())
                    ->method('decode')
                    ->with($foundUserData, $clue)
                    ->willReturn($credentialData);
        $sut  = new CredentialDataAdapterInDb($pdo, $dataDecoder);
        $fact = $sut->fetch('tester');
        self::assertInstanceOf(CredentialData::class, $fact);
        self::assertSame('tester', $fact->username());
    }
}
