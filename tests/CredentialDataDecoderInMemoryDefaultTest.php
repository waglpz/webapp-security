<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataDecoderInMemoryDefault;

final class CredentialDataDecoderInMemoryDefaultTest extends TestCase
{
    /** @test */
    public function itDecodeToNull(): void
    {
        $credDecoder = new CredentialDataDecoderInMemoryDefault();
        $data        = null;
        $clue        = 'tester';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);

        $credDecoder = new CredentialDataDecoderInMemoryDefault();
        $data        = [];
        $clue        = 'tester';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);

        $credDecoder = new CredentialDataDecoderInMemoryDefault();
        $data        = ['tester'];
        $clue        = '';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);

        $credDecoder = new CredentialDataDecoderInMemoryDefault();
        $data        = ['tester'];
        $clue        = 'tester';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);
    }

    /** @test */
    public function itDecodedValidData(): void
    {
        $credDecoder = new CredentialDataDecoderInMemoryDefault();
        $data        = [
            ['username' => 'tester', 'roles' => ['ROLE'], 'spaces' => ['SPACE'], 'passwordHash' => 'p4ssw0rd'],
            ['username' => 'tester_1', 'roles' => ['ROLE_1'], 'spaces' => ['SPACE_1'], 'passwordHash' => 'p4ssw0rd_1'],
        ];
        $clue        = 'tester';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertInstanceOf(CredentialData::class, $fact);
        self::assertSame('tester', $fact->username());
        self::assertSame(['ROLE'], $fact->roles());
        self::assertSame(['SPACE'], $fact->spaces());
        self::assertSame('p4ssw0rd', $fact->passwordHash());
    }
}
