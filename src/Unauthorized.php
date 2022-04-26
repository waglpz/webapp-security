<?php

declare(strict_types=1);

namespace Waglpz\Webapp\Security;

use Exception;

final class Unauthorized extends Exception
{
    /** @codingStandardsIgnoreStart */
    /** @var mixed */
    protected $message = 'Unauthorized';
    /** @var mixed */
    protected $code       = 401;
    /** @codingStandardsIgnoreEnd */
}
