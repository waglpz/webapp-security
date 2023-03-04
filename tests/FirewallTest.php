<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security\Tests;

use Generator;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Waglpz\Webapp\Security\Firewall;
use Waglpz\Webapp\Security\Forbidden;
use Waglpz\Webapp\Security\Role;

final class FirewallTest extends TestCase
{
    /** @test */
    public function hashesInUriUndRoute(): void
    {
        $uri                        = '/a1b2c3/abc';
        $_SESSION['hash_uri'][$uri] = '/a1b2c3';
        $regeln                     = ['/abc' => ['ROLLE_A']];
        $rollen                     = ['ROLLE_A'];
        $request                    = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())->method('getRequestTarget')->willReturn($uri);
        $firewall = new Firewall($regeln);

        $firewall->checkRules($request, $rollen);
    }

    /** @test */
    public function hashesInUriUndRouteForbidden(): void
    {
        $uri                        = '/a1b2c3/abc';
        $_SESSION['hash_uri'][$uri] = '/a1b2c3';
        $regeln                     = ['/abc' => ['ROLLE_A']];
        $rollen                     = ['ROLLE_B'];
        $request                    = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())->method('getRequestTarget')->willReturn($uri);
        $firewall = new Firewall($regeln);
        $this->expectException(Forbidden::class);
        $this->expectExceptionMessage('Forbidden');
        $firewall->checkRules($request, $rollen);
    }

    /**
     * @param array<string,array<string>> $regeln
     * @param array<string>               $rollen
     *
     * @dataProvider notAllowed
     * @test
     */
    public function throwsErrorIfRollenNotAllowedForRoute(string $uri, array $regeln, array $rollen): void
    {
        $this->expectException(Forbidden::class);
        $this->expectExceptionMessage('Forbidden');
        $this->expectExceptionCode(403);
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())->method('getRequestTarget')->willReturn($uri);
        $firewall = new Firewall($regeln);

        $firewall->checkRules($request, $rollen);
    }

    /**
     * @param array<string,array<string>> $regeln
     * @param array<string>               $rollen
     *
     * @dataProvider allowed
     * @test
     */
    public function noErrorIfRollenAllowedForRoute(string $uri, array $regeln, array $rollen): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::once())->method('getRequestTarget')->willReturn($uri);
        $firewall = new Firewall($regeln);

        $firewall->checkRules($request, $rollen);
    }

    /** @return Generator<mixed> */
    public static function notAllowed(): Generator
    {
        yield ['/a', ['/' => [Role::ROLE_NOT_AUTHENTICATED]], []];
        yield ['/a', ['/' => ['ROLLE_A']], ['ROLLE_B']];
        yield ['/a', ['/a' => ['ROLLE_A']], ['ROLLE_B']];
        yield ['/a', ['/a' => []], ['ROLLE_B']];
        yield ['/a', ['/a' => ['ROLLE_A']], []];
        yield ['/a', ['/a' => []], []];
        yield ['/a', ['/ab' => []], []];
        yield ['/ab', ['/a' => []], []];

        yield [
            '/a',
            [
                '/'   => ['ROLLE_B'],
                '/a'  => ['ROLLE_A'],
                '/ab' => ['ROLLE_B'],
            ],
            ['ROLLE_B'],
        ];

        yield [
            '/a',
            [
                '/'   => ['ROLLE_B'],
                '/ab' => ['ROLLE_B'],
                '/a'  => ['ROLLE_A'],
            ],
            ['ROLLE_B'],
        ];

        yield [
            '/a',
            [
                '/a'  => ['ROLLE_A'],
                '/'   => ['ROLLE_B'],
                '/ab' => ['ROLLE_B'],
            ],
            ['ROLLE_B'],
        ];

        yield [
            '/a',
            [
                '/a'  => ['ROLLE_A'],
                '/ab' => ['ROLLE_B'],
                '/'   => ['ROLLE_B'],
            ],
            ['ROLLE_B'],
        ];

        yield [
            '/a',
            [
                '/ab' => ['ROLLE_B'],
                '/a'  => ['ROLLE_A'],
                '/'   => ['ROLLE_B'],
            ],
            ['ROLLE_B'],
        ];

        yield [
            '/a',
            [
                '/ab' => ['ROLLE_B'],
                '/'   => ['ROLLE_B'],
                '/a'  => ['ROLLE_A'],
            ],
            ['ROLLE_B'],
        ];
    }

    /** @return Generator<mixed> */
    public static function allowed(): Generator
    {
        yield ['/a', ['/a' => [Role::ROLE_NOT_AUTHENTICATED]], [Role::ROLE_NOT_AUTHENTICATED]];
        yield ['/', ['/' => [Role::ROLE_NOT_AUTHENTICATED]], []];
        yield ['/', ['/' => [Role::ROLE_NOT_AUTHENTICATED]], ['ROLLE_A']];
        yield ['/', ['/' => ['ROLLE_A']], ['ROLLE_A']];
        yield ['/', ['/' => ['ROLLE_A', 'ROLLE_B']], ['ROLLE_A']];
        yield ['/', ['/' => ['ROLLE_A', 'ROLLE_B']], ['ROLLE_B']];
        yield ['/', ['/' => ['ROLLE_A', 'ROLLE_B']], ['ROLLE_A', 'ROLLE_B']];

        yield [
            '/a',
            [
                '/'   => ['ROLLE_B'],
                '/a'  => ['ROLLE_A'],
                '/ab' => ['ROLLE_B'],
            ],
            ['ROLLE_A'],
        ];

        yield [
            '/a',
            [
                '/'   => ['ROLLE_B'],
                '/ab' => ['ROLLE_B'],
                '/a'  => ['ROLLE_A'],
            ],
            ['ROLLE_A'],
        ];

        yield [
            '/a',
            [
                '/a'  => ['ROLLE_A'],
                '/'   => ['ROLLE_B'],
                '/ab' => ['ROLLE_B'],
            ],
            ['ROLLE_A'],
        ];

        yield [
            '/a',
            [
                '/a'  => ['ROLLE_A'],
                '/ab' => ['ROLLE_B'],
                '/'   => ['ROLLE_B'],
            ],
            ['ROLLE_A'],
        ];

        yield [
            '/a',
            [
                '/ab' => ['ROLLE_B'],
                '/a'  => ['ROLLE_A'],
                '/'   => ['ROLLE_B'],
            ],
            ['ROLLE_A'],
        ];

        yield [
            '/a',
            [
                '/ab' => ['ROLLE_B'],
                '/'   => ['ROLLE_B'],
                '/a'  => ['ROLLE_A'],
            ],
            ['ROLLE_A'],
        ];
    }
}
