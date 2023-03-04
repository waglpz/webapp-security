<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use PHPUnit\Framework\TestCase;
use Waglpz\Webapp\Security\CredentialData;
use Waglpz\Webapp\Security\CredentialDataDecoderInDbDefault;

final class CredentialDataDecoderInDbDefaultTest extends TestCase
{
    /** @test */
    public function itDecodeToNull(): void
    {
        $credDecoder = new CredentialDataDecoderInDbDefault();
        $data        = null;
        $clue        = '';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);

        $credDecoder = new CredentialDataDecoderInDbDefault();
        $data        = null;
        $clue        = 'tester';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);

        $credDecoder = new CredentialDataDecoderInDbDefault();
        $data        = new \stdClass();
        $clue        = '';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);

        $credDecoder = new CredentialDataDecoderInDbDefault();
        $data        = new \stdClass();
        $clue        = 'tester';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);

        $credDecoder    = new CredentialDataDecoderInDbDefault();
        $data           = new \stdClass();
        $data->username = 'no_tester';
        $clue           = '';
        $fact           = $credDecoder->decode($data, $clue);
        self::assertNull($fact);

        $credDecoder = new CredentialDataDecoderInDbDefault();
        $data        = [];
        $clue        = 'tester';
        $fact        = $credDecoder->decode($data, $clue);
        self::assertNull($fact);
    }

    /** @test */
    public function itDecodedValidData(): void
    {
        $credDecoder        = new CredentialDataDecoderInDbDefault();
        $data               = new \stdClass();
        $data->username     = 'tester';
        $data->role         = ['ROLE'];
        $data->spaces       = ['SPACE'];
        $data->passwordHash = 'p4ssw0rd';
        $clue               = 'tester';
        $fact               = $credDecoder->decode($data, $clue);
        self::assertInstanceOf(CredentialData::class, $fact);
        self::assertSame('tester', $fact->username());
        self::assertSame(['ROLE'], $fact->roles());
        self::assertSame(['SPACE'], $fact->spaces());
        self::assertSame('p4ssw0rd', $fact->passwordHash());
    }
}
