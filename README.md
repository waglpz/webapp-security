Waglpz WebApp Security Component
================================

![PHP Checked](https://github.com/waglpz/webapp-security/workflows/PHP%20Composer/badge.svg)


Install via composer
--------------------

`composer require waglpz/webapp-security`

Working with sources within Docker
----------------------------------

Clone Project in some Directory `git clone https://github.com/waglpz/webapp-security.git` 

Go into Directory `webapp-security` and run: `bash ./bin/start.sh` to start working within Docker Container.

To stop and clean run: `bash ./bin/clean.sh`

##### Composer using from Docker Container
 1. Install Vendor Dependencies `composer install`
 2. Display Waglpz Composer commands: `composer list | grep waglpz`
    1. Check Source Code vitality: `composer waglpz:check:normal` 
    1. Check Source Code Styles: `waglpz:cs-check`
    1. Automatic fix Source Code Styles Errors: `waglpz:cs-fix`

#### Authentication Basic for an API

How to authenticate a User from HTTP Request as a Gherkin Szenario

```gherkin
Szenario: Basic Authentication
    Given: HTTP Request contains 'PHP_AUTH_USER' and 'PHP_AUTH_PW'
    And: We have an Instance of `\Waglpz\Webapp\Security\Authenticator`
    And: We have dependency Instance of `Waglpz\Webapp\Security\UserAuthDataAdapter` injected in `\Waglpz\Webapp\Security\Authenticator`
    When: Runtime call `\Waglpz\Webapp\Security\Authenticator::authenticate(ServerRequestInterface)`
    And: User found via `\Waglpz\Webapp\Security\UserAuthDataAdapter` 
    Then: `Waglpz\Webapp\Security\Authenticator::authenticate(ServerRequestInterface) returns boolean true
```
Example PHP code

```php
$users = [
    [
        'username' => 'tester@akme.com',
        'role' => 'ROLE_TESTER',
        'password' => 'xxxxxx123',
    ],
];
$authDataAdapter = new \Waglpz\Webapp\Security\CredentialDataAdapterInMemory($users);
$authenticator = new \Waglpz\Webapp\Security\AuthenticatorBasic($authDataAdapter);

/*
 * $request contains valid user "tester@akme.com" and password "xxxxxx123"
 */
$request;
\assert($request instanceof \Psr\Http\Message\ServerRequestInterface);

$authResult = $authenticator->authenticate($request);

\assert($authResult);
\assert($authenticator->username() === 'tester@akme.com');
```

#### Find exist User Roles 

How to find Role of a User as a Gherkin Szenario

```gherkin
Szenario: Find User Role
    Given: We have an Instance of `\Waglpz\Webapp\Security\UserAuthRolesProvider`
    And: We have dependency Instance of `Waglpz\Webapp\Security\UserAuthDataAdapter` injected in `\Waglpz\Webapp\Security\UserAuthRolesProvider`
    When: Runtime call `\Waglpz\Webapp\Security\UserAuthRolesProvider::findRole(?string)`
    And: User found via `Waglpz\Webapp\Security\UserAuthDataAdapter` 
    Then: `\Waglpz\Webapp\Security\UserAuthRolesProvider::findRole(?string) returns array of Roles
```

Example PHP code

```php

$users = [
    [
        'username' => 'tester@akme.com',
        'role' => 'ROLE_TESTER',
        'password' => 'xxxxxx123',
    ],
];
$authDataAdapter = new \Waglpz\Webapp\Security\CredentialDataAdapterInMemory($users);
$rolesFinder = new \Waglpz\Webapp\Security\UserAuthRolesProvider($authDataAdapter);

$roles = $rolesFinder->findRole('tester@akme.com');

\assert($roles === ['ROLE_TESTER'])

```

#### Routing Firewall

How to secure the Route by Role of a User as a Gherkin Szenario

```gherkin
Szenario: Secure the Route by Firewall
    Given: We have an Instance of `\Waglpz\Webapp\Security\Firewall`
    And: We have a array of Firewall Rules injected in `\Waglpz\Webapp\Security\Firewall`
    When: Runtime call `\Waglpz\Webapp\Security\Firewall::checkRules(ServerRequestInterface, roles)`
    And: User roles matches Firewall Rules  
    Then: No Forbidden 403 Exception was thrown.
```

Example PHP code

```php

$rules = [
    '/abc-route' => ['ROLE_TESTER'],
];
$users = [
    [
        'username' => 'tester@akme.com',
        'role' => 'ROLE_TESTER',
        'password' => 'xxxxxx123',
    ],
];
$authDataAdapter = new \Waglpz\Webapp\Security\CredentialDataAdapterInMemory($users);
$rolesFinder = new \Waglpz\Webapp\Security\UserAuthRolesProvider($authDataAdapter);

$roles = $rolesFinder->findRole('tester@akme.com');

\assert($roles === ['ROLE_TESTER'])

$firewall = new \Waglpz\Webapp\Security\Firewall($rules);

$request;
\assert($request instanceof \Psr\Http\Message\ServerRequestInterface);

try {
    $firewall->checkRules($request,$currentRoles);
} catch (\Waglpz\Webapp\Security\Forbidden $exception) {
    // this block will not execute, because user current role was matched for route in rules 
}


```
