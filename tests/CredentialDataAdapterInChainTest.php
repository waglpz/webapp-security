<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\MockObject\Rule\InvocationOrder;
use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataAdapterInChain;
use Waglpz\Webapp\Security\CredentialDataAdapterInDb;
use Waglpz\Webapp\Security\CredentialDataAdapterInMemory;
use Waglpz\Webapp\Security\CredentialDataAdapterJWT;
use Waglpz\Webapp\Security\CredentialDataDecoderInDbDefault;
use Waglpz\Webapp\Security\CredentialDataDecoderInMemoryDefault;

final class CredentialDataAdapterInChainTest extends TestCase
{
    /** @test */
    public function itNothingFoundInChain(): void
    {
        $token            = 'a.b.c';
        $header           = 'Bearer ' . $token;
        $jwtCredDataFound = null;

        $inDbDataFound           = new \stdClass();
        $inDbDataFound->username = 'tester_db';

        $inMemoryData = [
            ['username' => 'tester_in_mem_1'],
            ['username' => 'tester_in_mem_2'],
        ];

        $request          = $this->request($header, self::once());
        $pdo              = $this->pdo($inDbDataFound, self::once());
        $inJWTDataDocoder = $this->JWTDataDocoder($token, $jwtCredDataFound, self::once());

        $nMemoryDataDecoder     = new CredentialDataDecoderInMemoryDefault();
        $dataInDbDecoder        = new CredentialDataDecoderInDbDefault();
        $credentialDataAdapters = [
            new CredentialDataAdapterJWT($request, $inJWTDataDocoder),
            new CredentialDataAdapterInMemory($inMemoryData, $nMemoryDataDecoder),
            new CredentialDataAdapterInDb($pdo, $dataInDbDecoder),
        ];

        $sut  = new CredentialDataAdapterInChain($credentialDataAdapters);
        $fact = $sut->fetch('teste');
        self::assertNull($fact);
    }

    /** @test */
    public function itFoundInFirstInChain(): void
    {
        $token  = 'a.b.c';
        $header = 'Bearer ' . $token;

        $inDbData           = new \stdClass();
        $inDbData->username = 'tester_db';

        $inMemoryData = [
            ['username' => 'tester_in_mem_1'],
            ['username' => 'tester_in_mem_2'],
        ];

        $request = $this->request($header, self::once());
        $pdo     = $this->pdo($inDbData, self::never());

        $jwtCredDataFound = new CredentialData('jwt_tester');
        $inJWTDataDocoder = $this->JWTDataDocoder($token, $jwtCredDataFound, self::once());

        $nMemoryDataDecoder     = new CredentialDataDecoderInMemoryDefault();
        $dataInDbDecoder        = new CredentialDataDecoderInDbDefault();
        $credentialDataAdapters = [
            new CredentialDataAdapterJWT($request, $inJWTDataDocoder),
            new CredentialDataAdapterInMemory($inMemoryData, $nMemoryDataDecoder),
            new CredentialDataAdapterInDb($pdo, $dataInDbDecoder),
        ];

        $sut  = new CredentialDataAdapterInChain($credentialDataAdapters);
        $fact = $sut->fetch();
        self::assertInstanceOf(CredentialData::class, $fact);
        self::assertSame('jwt_tester', $fact->username());
    }

    /** @test */
    public function itFoundInSecondInChain(): void
    {
        $token  = 'a.b.c';
        $header = 'Bearer ' . $token;

        $inDbData           = new \stdClass();
        $inDbData->username = 'tester_db';

        $inMemoryData = [
            ['username' => 'tester_in_mem_1'],
            ['username' => 'tester_in_mem_2'],
        ];

        $request = $this->request($header, self::once());
        $pdo     = $this->pdo($inDbData, self::never());

        $jwtCredDataFound = null;
        $inJWTDataDocoder = $this->JWTDataDocoder($token, $jwtCredDataFound, self::once());

        $nMemoryDataDecoder     = new CredentialDataDecoderInMemoryDefault();
        $dataInDbDecoder        = new CredentialDataDecoderInDbDefault();
        $credentialDataAdapters = [
            new CredentialDataAdapterJWT($request, $inJWTDataDocoder),
            new CredentialDataAdapterInMemory($inMemoryData, $nMemoryDataDecoder),
            new CredentialDataAdapterInDb($pdo, $dataInDbDecoder),
        ];

        $sut  = new CredentialDataAdapterInChain($credentialDataAdapters);
        $fact = $sut->fetch('tester_in_mem_2');
        self::assertInstanceOf(CredentialData::class, $fact);
        self::assertSame('tester_in_mem_2', $fact->username());
    }

    /** @test */
    public function itFoundInThirdInChain(): void
    {
        $header           = '';
        $token            = '';
        $jwtCredDataFound = null;

        $inMemoryData = [];

        $inDbDataFound           = new \stdClass();
        $inDbDataFound->username = 'tester_db';

        $request = $this->request($header, self::once());
        $pdo     = $this->pdo($inDbDataFound, self::once());

        $inJWTDataDocoder = $this->JWTDataDocoder($token, $jwtCredDataFound, self::never());

        $nMemoryDataDecoder     = new CredentialDataDecoderInMemoryDefault();
        $dataInDbDecoder        = new CredentialDataDecoderInDbDefault();
        $credentialDataAdapters = [
            new CredentialDataAdapterJWT($request, $inJWTDataDocoder),
            new CredentialDataAdapterInMemory($inMemoryData, $nMemoryDataDecoder),
            new CredentialDataAdapterInDb($pdo, $dataInDbDecoder),
        ];

        $sut  = new CredentialDataAdapterInChain($credentialDataAdapters);
        $fact = $sut->fetch('tester_db');
        self::assertInstanceOf(CredentialData::class, $fact);
        self::assertSame('tester_db', $fact->username());
    }

    private function request(
        string $header,
        InvocationOrder $order,
    ): \PHPUnit\Framework\MockObject\MockObject & \Psr\Http\Message\ServerRequestInterface {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->expects($order)
                ->method('getHeaderLine')
                ->with('Authorization')
                ->willReturn($header);

        return $request;
    }

    private function pdo(
        \stdClass|null $inDbData,
        InvocationOrder $order,
    ): \PHPUnit\Framework\MockObject\MockObject & \PDO {
        $pdo = $this->createMock(\PDO::class);
        $sth = $this->createMock(\PDOStatement::class);
        $sth->expects(self::any())->method('execute');
        $sth->expects(self::any())
            ->method('fetch')
            ->with(\PDO::FETCH_OBJ)
            ->willReturn($inDbData);
        $pdo->expects($order)
            ->method('prepare')
            ->with(self::isType('string'))
            ->willReturn($sth);

        return $pdo;
    }

    private function JWTDataDocoder(
        string $token,
        CredentialData|null $return,
        InvocationOrder $order,
    ): \Waglpz\Webapp\Security\JWTDecoder & \PHPUnit\Framework\MockObject\MockObject {
        $inJWTDataDocoder = $this->createMock(\Waglpz\Webapp\Security\JWTDecoder::class);
        $inJWTDataDocoder->expects($order)
                         ->method('decode')
                         ->with($token)
                         ->willReturn($return);

        return $inJWTDataDocoder;
    }
}
