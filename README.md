# OpenID Connect (OIDC) Client

[![Latest Version on Packagist](https://img.shields.io/packagist/v/leondg/oidc-client.svg?style=flat-square)](https://packagist.org/packages/leondg/oidc-client)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Tests](https://github.com/leondg/oidc-client/workflows/Tests/badge.svg)](https://github.com/leondg/oidc-client/actions)

A modern, robust OpenID Connect (OIDC) client for PHP, built on top of [The PHP League's OAuth 2.0 Client](https://oauth2-client.thephpleague.com/). This package automates OIDC discovery and provides seamless integration with any PSR-16 compatible cache.

## Features

- **Automated Discovery:** Automatically fetch and parse OIDC configuration from `.well-known/openid-configuration`.
- **Full Specification Support:** Support for over 30 metadata fields including logout, introspection, and revocation.
- **Secure ID Token Validation:** Built-in JWT verification using JWKS and standard claim checks (`iss`, `aud`, `exp`, `nonce`).
- **PSR-16 Caching:** Seamlessly cache discovery documents to eliminate redundant network requests.
- **PKCE & Nonce:** Native support for Proof Key for Code Exchange and Nonce to prevent replay attacks.
- **Efficient Resource Owner:** Initialize user profiles directly from ID Token claims without extra UserInfo API calls.
- **Type-Safe:** Fully type-hinted and compatible with PHP ^7.4 || ^8.0.
- **Extensible:** Based on `GenericProvider`, allowing for custom collaborator injection.

## Installation

Install the package via Composer:

```bash
composer require leondg/oidc-client
```

## Usage

### Basic Example

```php
use Leondg\Oidc\Client\Provider\WellKnownConfig;
use Leondg\Oidc\Client\Provider\OpenIDConnectProvider;

$discoverUri = 'https://auth.example.com/v2';
$clientId = 'your-client-id';
$clientSecret = 'your-client-secret';
$redirectUri = 'https://mywebsite.example.com/';
$scopes = ['openid', 'profile', 'email'];

// 1. Fetch OIDC Configuration
$config = WellKnownConfig::create($discoverUri);

// 2. Initialize the Provider
$provider = new OpenIDConnectProvider(
    $config,
    $clientId,
    $clientSecret,
    $redirectUri,
    $scopes
);

// 3. Get Authorization URL (with Nonce)
$nonce = bin2hex(random_bytes(16));
$_SESSION['oidc_nonce'] = $nonce;

$authUrl = $provider->getAuthorizationUrl([
    'nonce' => $nonce
]);
```

### Validating ID Tokens

OIDC requires the validation of the ID Token (JWT) returned by the provider. This package handles signature verification (via JWKS) and standard claim checks (`iss`, `aud`, `exp`, `nonce`). You can also provide a `leeway` (in seconds) to account for clock skew between servers:

```php
try {
    $idToken = $_POST['id_token']; // Or from token response
    $nonce = $_SESSION['oidc_nonce']; 
    
    // Validate with 60 seconds leeway for clock skew
    $claims = $provider->validateIdToken($idToken, $nonce, 60);
    
    echo "Welcome, " . $claims->sub;
} catch (\Exception $e) {
    // Token is invalid
    die($e->getMessage());
}
```

### Efficient Resource Owner Retrieval

In OIDC, the ID Token often contains all the user information you need. You can initialize the `OpenIDConnectResourceOwner` directly from the validated claims, avoiding an unnecessary network request to the UserInfo endpoint:

```php
$claims = $provider->validateIdToken($idToken, $nonce);
$user = $provider->getResourceOwnerFromIdToken($claims);

echo $user->getEmail();
echo $user->getName();
```

### Logout (RP-Initiated)

Generate a logout URL for the user:

```php
$logoutUrl = $provider->getLogoutUrl([
    'id_token_hint' => $idToken,
    'post_logout_redirect_uri' => 'https://mywebsite.example.com/logout-callback'
]);

// Redirect the user to $logoutUrl
header('Location: ' . $logoutUrl);
```

### With Caching (Recommended)

To avoid fetching the OIDC configuration on every request, you can pass any PSR-16 `CacheInterface` implementation:

```php
// Assuming $cache is an instance of Psr\SimpleCache\CacheInterface
$config = WellKnownConfig::create($discoverUri, $cache, 3600);
```

### With PKCE

```php
$provider = new OpenIDConnectProvider(
    $config,
    $clientId,
    $clientSecret,
    $redirectUri,
    $scopes,
    OpenIDConnectProvider::PKCE_METHOD_S256
);
```

## Testing

The package includes a comprehensive test suite. You can run the tests using PHPUnit:

```bash
composer test
```

## Static Analysis

We use PHPStan for static analysis to ensure code quality:

```bash
composer analyze
```

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
