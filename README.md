# oidc-client

This package provides OpenID Connect Well-Known Configuration support based on The PHP League's OAuth 2.0 Client.  
_Please note that this package is very basic and far from perfect_  
_If you want to contribute or have suggestions you are welcome to provide them_

## Usage examples:
```php
$discoverUri = 'https://auth.example.com/v2';
$clientId = 'your-client-id';
$clientSecret = 'your-client-secret';
$redirectUri = 'https://mywebsite.example.com/'
$scopes = ['openid'];

$config = WellKnownConfig::create($discoverUri);
$provider = new OpenIDConnectProvider(
    $config,
    $clientId,
    $clientSecret,
    $redirectUri,
    $scopes
);
```
    
**[Recommended]** If you want to use PKCE you can add the following constant:
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

Now you can retrieve the authorization url with:
```php
$provider->getAuthorizationUrl();
```

Here you can find more examples and basic usage:  
https://oauth2-client.thephpleague.com/usage/
