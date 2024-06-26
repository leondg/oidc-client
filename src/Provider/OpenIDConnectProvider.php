<?php

declare(strict_types=1);

namespace Leondg\Oidc\Client\Provider;

use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;
use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;

class OpenIDConnectProvider extends GenericProvider
{
    /**
     * @var string
     */
    private $responseResourceOwnerId = 'sub';

    public function __construct(
        WellKnownConfig $config,
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        array $scopes,
        string $pkceMethod = null
    ) {
        $this->redirectUri = $redirectUri;

        parent::__construct(
            $this->createOptions($config, $clientId, $clientSecret, $scopes, $pkceMethod),
            $this->createCollaborators($config)
        );
    }

    private function createCollaborators(WellKnownConfig $config): array
    {
        $collaborators = [];

        if ($config->hasTokenEndpointAuthMethodSupport(WellKnownConfig::AUTH_CLIENT_SECRET_BASIC)) {
            $collaborators['optionProvider'] = new HttpBasicAuthOptionProvider();
        } elseif ($config->hasTokenEndpointAuthMethodSupport(WellKnownConfig::AUTH_CLIENT_SECRET_POST)) {
            $collaborators['optionProvider'] = new PostAuthOptionProvider();
        }

        return $collaborators;
    }

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new OpenIDConnectResourceOwner($response, $this->responseResourceOwnerId);
    }

    private function createOptions(
        WellKnownConfig $config,
        string $clientId,
        string $clientSecret,
        array $scopes,
        string $pkceMethod
    ): array {
        return [
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'urlAuthorize' => $config->getAuthorizationEndpoint(),
            'urlAccessToken' => $config->getTokenEndpoint(),
            'urlResourceOwnerDetails' => $config->getUserinfoEndpoint(),
            'scopes' => $scopes,
            'pkceMethod' => $pkceMethod
        ];
    }
}
