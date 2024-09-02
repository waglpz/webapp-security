<?php

declare(strict_types=1);

return [
    '/api/doc' => ['ROLE_NOT_AUTHENTICATED'],
    '/*'       => ['ROLE_NOT_AUTHENTICATED'],
    '/'        => ['ROLE_NOT_AUTHENTICATED'],
];
