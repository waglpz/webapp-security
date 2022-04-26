<?php
/** @noinspection PhpMissingFieldTypeInspection */

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Exception;

final class Forbidden extends Exception
{
    /** @codingStandardsIgnoreStart */
    /** @var mixed */
    protected $message = 'Forbidden';
    /** @var mixed */
    protected $code       = 403;
    /** @codingStandardsIgnoreEnd */
}
