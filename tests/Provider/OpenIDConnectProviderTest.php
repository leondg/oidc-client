<?php

declare(strict_types=1);

namespace Leondg\Oidc\Client\Tests\Provider;

use Leondg\Oidc\Client\Provider\OpenIDConnectProvider;
use Leondg\Oidc\Client\Provider\WellKnownConfig;
use PHPUnit\Framework\TestCase;

class OpenIDConnectProviderTest extends TestCase
{
    private WellKnownConfig $config;
    private OpenIDConnectProvider $provider;

    protected function setUp(): void
    {
        $this->config = (new WellKnownConfig())
            ->setAuthorizationEndpoint('https://example.com/auth')
            ->setTokenEndpoint('https://example.com/token')
            ->setUserinfoEndpoint('https://example.com/userinfo')
            ->setEndSessionEndpoint('https://example.com/logout')
            ->setIssuer('https://example.com');

        $this->provider = new OpenIDConnectProvider(
            $this->config,
            'client-id',
            'client-secret',
            'https://redirect.com',
            ['openid']
        );
    }

    public function testGetLogoutUrl(): void
    {
        $logoutUrl = $this->provider->getLogoutUrl([
            'id_token_hint' => 'fake-token',
            'post_logout_redirect_uri' => 'https://redirect.com/after-logout'
        ]);

        $this->assertStringContainsString('https://example.com/logout', $logoutUrl);
        $this->assertStringContainsString('id_token_hint=fake-token', $logoutUrl);
        $this->assertStringContainsString('post_logout_redirect_uri=https%3A%2F%2Fredirect.com%2Fafter-logout', $logoutUrl);
    }

    public function testGetLogoutUrlThrowsExceptionWhenNotSupported(): void
    {
        $config = new WellKnownConfig();
        $provider = new OpenIDConnectProvider($config, 'id', 'secret', 'uri', []);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('End session endpoint is not supported by this provider.');
        $provider->getLogoutUrl();
    }
}
