<?php

declare(strict_types=1);

namespace Leondg\Oidc\Client\Provider;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as HttpClient;
use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;
use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;

class OpenIDConnectProvider extends GenericProvider
{
    private WellKnownConfig $config;

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
        ?string $pkceMethod = null,
        string $scopeSeparator = ' '
    ) {
        $this->config = $config;
        $this->redirectUri = $redirectUri;

        parent::__construct(
            $this->createOptions($config, $clientId, $clientSecret, $scopes, $pkceMethod, $scopeSeparator),
            $this->createCollaborators($config)
        );
    }

    public function getAuthorizationUrl(array $options = []): string
    {
        $url = parent::getAuthorizationUrl($options);

        if (isset($options['nonce'])) {
            $query = parse_url($url, PHP_URL_QUERY);
            $newQuery = $query ? $query . '&nonce=' . $options['nonce'] : 'nonce=' . $options['nonce'];
            $url = str_replace($query, $newQuery, $url);
        }

        return $url;
    }

    public function getLogoutUrl(array $options = []): string
    {
        $base = $this->config->getEndSessionEndpoint();
        if ($base === null) {
            throw new \LogicException('End session endpoint is not supported by this provider.');
        }

        $params = [];
        if (isset($options['id_token_hint'])) {
            $params['id_token_hint'] = $options['id_token_hint'];
        }
        if (isset($options['post_logout_redirect_uri'])) {
            $params['post_logout_redirect_uri'] = $options['post_logout_redirect_uri'];
        }
        if (isset($options['state'])) {
            $params['state'] = $options['state'];
        }

        $query = http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        return $base . ($query ? '?' . $query : '');
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
        ?string $pkceMethod,
        string $scopeSeparator = ' '
    ): array {
        return [
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'urlAuthorize' => $config->getAuthorizationEndpoint(),
            'urlAccessToken' => $config->getTokenEndpoint(),
            'urlResourceOwnerDetails' => $config->getUserinfoEndpoint(),
            'scopes' => $scopes,
            'pkceMethod' => $pkceMethod,
            'scopeSeparator' => $scopeSeparator
        ];
    }

    /**
     * Validates an OIDC ID Token.
     *
     * @param string $idToken The raw JWT ID Token.
     * @param string|null $nonce The nonce used during the authorization request (if any).
     * @param int $leeway Clock skew tolerance in seconds.
     * @return object The decoded token claims.
     * @throws \Exception If the token is invalid or the provider configuration is missing required endpoints.
     */
    public function validateIdToken(string $idToken, ?string $nonce = null, int $leeway = 0): object
    {
        $jwksUri = $this->config->getJwksUri();
        if ($jwksUri === null) {
            throw new \LogicException('JWKS URI is not supported by this provider.');
        }

        $issuer = $this->config->getIssuer();
        if ($issuer === null) {
            throw new \LogicException('Issuer is not supported by this provider.');
        }

        $jwks = $this->fetchJwks($jwksUri);
        $keys = JWK::parseKeySet($jwks);

        if ($leeway > 0) {
            JWT::$leeway = $leeway;
        }

        $decoded = JWT::decode($idToken, $keys);

        // Standard OIDC claim checks
        if ($decoded->iss !== $issuer) {
            throw new \Exception('Invalid issuer in ID Token.');
        }

        $aud = (array) $decoded->aud;
        if (!in_array($this->clientId, $aud, true)) {
            throw new \Exception('Invalid audience in ID Token.');
        }

        if ($nonce !== null && (!isset($decoded->nonce) || $decoded->nonce !== $nonce)) {
            throw new \Exception('Invalid nonce in ID Token.');
        }

        return $decoded;
    }

    /**
     * Creates a Resource Owner from the ID Token claims.
     *
     * @param object $claims The decoded ID Token claims.
     * @return OpenIDConnectResourceOwner
     */
    public function getResourceOwnerFromIdToken(object $claims): OpenIDConnectResourceOwner
    {
        return new OpenIDConnectResourceOwner((array) $claims, $this->responseResourceOwnerId);
    }

    /**
     * Fetches JWKS from the provider.
     *
     * @param string $uri
     * @return array
     */
    private function fetchJwks(string $uri): array
    {
        $response = (new HttpClient())->get($uri);
        $content = $response->getBody()->getContents();

        return json_decode($content, true, 512, JSON_THROW_ON_ERROR);
    }
}
