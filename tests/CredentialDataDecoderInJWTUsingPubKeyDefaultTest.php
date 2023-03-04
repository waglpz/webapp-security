<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataDecoderInJWTUsingPubKeyDefault;

final class CredentialDataDecoderInJWTUsingPubKeyDefaultTest extends TestCase
{
    /**
     * @test
     * @dataProvider tokenForTest
     */
    public function decodeToken(string $token, \Closure $assertCallback): void
    {
        $publicKeyFile = __DIR__ . '/stubs/public_key';

        $sut  = new CredentialDataDecoderInJWTUsingPubKeyDefault($publicKeyFile);
        $fact = $sut->decode($token);
        $assertCallback($fact);
    }

    /** @test */
    public function itThrowsAnExceptionIfKeyFileInvalid(): void
    {
        $publicKeyFile = 'wrong';
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Public KEY file does not exist or not readable.');
        (new CredentialDataDecoderInJWTUsingPubKeyDefault($publicKeyFile));
    }

    /** @test */
    public function itThrowsAnExceptionIfTokenExpired(): void
    {
        $publicKeyFile  = __DIR__ . '/stubs/public_key';
        $privateKeyFile = __DIR__ . '/stubs/private_key';
        $privateKey     = \file_get_contents($privateKeyFile);
        \assert(\is_string($privateKey));
        $token = JWT::encode(
            [
                'exp' => (new \DateTimeImmutable())->modify('-1 sec')->format('U'),
            ],
            $privateKey,
            'RS256',
        );

        $this->expectException(ExpiredException::class);
        $this->expectExceptionMessage('Expired token');
        (new CredentialDataDecoderInJWTUsingPubKeyDefault($publicKeyFile))->decode($token);
    }

    /** @return \Generator<mixed> */
    public static function tokenForTest(): \Generator
    {
        $privateKeyFile = __DIR__ . '/stubs/private_key';
        $privateKey     = \file_get_contents($privateKeyFile);
        \assert(\is_string($privateKey));

        yield 'not yet expired and full user data' => [
            JWT::encode(
                [
                    'exp'      => (new \DateTimeImmutable())->modify('+5 sec')->format('U'),
                    'userData' => [
                        'email'        => 'tester@akme.com',
                        'roles'        => ['ROLE_A', 'ROLE_B'],
                        'spaces'       => ['A', 'B', 'C'],
                        'passwordHash' => 'pwhash',
                    ],
                ],
                $privateKey,
                'RS256',
            ),
            static function (mixed $fact): void {
                self::assertInstanceOf(CredentialData::class, $fact);
                self::assertSame('tester@akme.com', $fact->username());
                self::assertSame(['ROLE_A', 'ROLE_B'], $fact->roles());
                self::assertSame(['A', 'B', 'C'], $fact->spaces());
                self::assertSame('pwhash', $fact->passwordHash());
            },
        ];

        yield 'not yet expired and email ok' => [
            JWT::encode(
                [
                    'exp'      => (new \DateTimeImmutable())->modify('+5 sec')->format('U'),
                    'userData' => ['email' => 'tester@akme.com'],
                ],
                $privateKey,
                'RS256',
            ),
            static function (mixed $fact): void {
                self::assertInstanceOf(CredentialData::class, $fact);
                self::assertSame('tester@akme.com', $fact->username());
            },
        ];

        yield 'not yet expired and email not exists' => [
            JWT::encode(
                [
                    'exp'      => (new \DateTimeImmutable())->modify('+5 sec')->format('U'),
                    'userData' => [],
                ],
                $privateKey,
                'RS256',
            ),
            static function (mixed $fact): void {
                self::assertNull($fact);
            },
        ];

        yield 'not yet expired and userData not exists' => [
            JWT::encode(
                [
                    'exp' => (new \DateTimeImmutable())->modify('+5 sec')->format('U'),
                ],
                $privateKey,
                'RS256',
            ),
            static function (mixed $fact): void {
                self::assertNull($fact);
            },
        ];

        yield 'empty token' => [
            '',
            static function (mixed $fact): void {
                self::assertNull($fact);
            },
        ];
    }
}
