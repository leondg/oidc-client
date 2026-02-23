<?php

declare(strict_types=1);

namespace Leondg\Oidc\Client\Tests\Provider;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Psr7\Response;
use Leondg\Oidc\Client\Provider\WellKnownConfig;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;

class WellKnownConfigTest extends TestCase
{
    private string $json;

    protected function setUp(): void
    {
        $this->json = json_encode([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/auth',
            'token_endpoint' => 'https://example.com/token',
            'userinfo_endpoint' => 'https://example.com/userinfo',
            'jwks_uri' => 'https://example.com/jwks',
            'response_types_supported' => ['code', 'id_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);
    }

    public function testGettersAndSetters(): void
    {
        $config = new WellKnownConfig();
        $config->setIssuer('https://test.com');
        $this->assertEquals('https://test.com', $config->getIssuer());
        
        $config->setAuthorizationEndpoint('https://test.com/auth');
        $this->assertEquals('https://test.com/auth', $config->getAuthorizationEndpoint());
    }

    public function testHasTokenEndpointAuthMethodSupport(): void
    {
        $config = new WellKnownConfig();
        $config->setTokenEndpointAuthMethodsSupported(['client_secret_basic', 'client_secret_post']);
        
        $this->assertTrue($config->hasTokenEndpointAuthMethodSupport('client_secret_basic'));
        $this->assertTrue($config->hasTokenEndpointAuthMethodSupport('client_secret_post'));
        $this->assertFalse($config->hasTokenEndpointAuthMethodSupport('private_key_jwt'));
    }

    public function testNewOidcFields(): void
    {
        $config = new WellKnownConfig();
        $config->setIntrospectionEndpoint('https://test.com/introspect');
        $config->setRevocationEndpoint('https://test.com/revoke');
        $config->setCodeChallengeMethodsSupported(['S256']);

        $this->assertEquals('https://test.com/introspect', $config->getIntrospectionEndpoint());
        $this->assertEquals('https://test.com/revoke', $config->getRevocationEndpoint());
        $this->assertTrue($config->hasCodeChallengeMethodSupport('S256'));
        $this->assertFalse($config->hasCodeChallengeMethodSupport('plain'));
    }

    public function testLogoutFields(): void
    {
        $config = new WellKnownConfig();
        $config->setFrontchannelLogoutSupported(true);
        $config->setBackchannelLogoutSupported(true);

        $this->assertTrue($config->isFrontchannelLogoutSupported());
        $this->assertTrue($config->isBackchannelLogoutSupported());
    }

    public function testCreateWithCache(): void
    {
        $cache = $this->createMock(CacheInterface::class);
        $cachedConfig = new WellKnownConfig();
        $cachedConfig->setIssuer('https://cached.com');

        $cache->expects($this->once())
            ->method('has')
            ->willReturn(true);

        $cache->expects($this->once())
            ->method('get')
            ->willReturn($cachedConfig);

        $config = WellKnownConfig::create('https://example.com', $cache);
        $this->assertEquals('https://cached.com', $config->getIssuer());
    }
}
