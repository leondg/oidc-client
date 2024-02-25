<?php

declare(strict_types=1);

namespace Leondg\Oidc\Client\Provider;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Component\Serializer\Serializer;

class WellKnownConfig
{
    public const CONFIG_LOCATION = '/.well-known/openid-configuration';
    public const CONFIG_FORMAT = 'json';
    public const AUTH_CLIENT_SECRET_BASIC = 'client_secret_basic';
    public const AUTH_CLIENT_SECRET_POST = 'client_secret_post';

    /**
     * @var string
     * REQUIRED. URL using the https scheme with no query or fragment component
     * that the OP asserts as its Issuer Identifier.
     * If Issuer discovery is supported (see Section 2), this value MUST be identical
     * to the issuer value returned by WebFinger.
     * This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
     */
    private string $issuer;

    /**
     * @var string
     * REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
     */
    private string $authorizationEndpoint;

    /**
     * @var string
     * URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit Flow is used.
     */
    private string $tokenEndpoint;

    /**
     * @var string
     * REQUIRED IF OpenID Connect Provider supports OpenID Connect Session Management and is a URL at the OP
     * to which an RP can perform a redirect to request that the End-User be logged out at the OP
     */
    private string $endSessionEndpoint;

    /**
     * @var string
     * RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core].
     * This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
     */
    private string $userinfoEndpoint;

    /**
     * @var string
     * REQUIRED. URL of the OP's JSON Web Key Set [JWK] document.
     * This contains the signing key(s) the RP uses to validate signatures from the OP.
     * The JWK Set MAY also contain the Server's encryption key(s),
     * which are used by RPs to encrypt requests to the Server.
     * When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED
     * for all keys in the referenced JWK Set to indicate each key's intended usage.
     * Although some algorithms allow the same key to be used for both signatures and encryption,
     * doing so is NOT RECOMMENDED, as it is less secure.
     * The JWK x5c parameter MAY be used to provide X.509 representations of keys provided.
     * When used, the bare key values MUST still be present and MUST match those in the certificate.
     */
    private string $jwksUri;

    /**
     * @var string
     * RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].
     */
    private string $registrationEndpoint;

    /**
     * @var array
     * RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports.
     * The server MUST support the openid scope value. Servers MAY choose not to advertise some supported scope values
     * even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
     */
    private array $scopesSupported;

    /**
     * @var array
     * REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.
     * Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
     */
    private array $responseTypesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports,
     * as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses].
     * If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
     */
    private array $responseModesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
     * Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values
     * and MAY support other Grant Types. If omitted, the default value is ["authorization_code", "implicit"].
     */
    private array $grantTypesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
     */
    private array $acrValuesSupported;

    /**
     * @var array
     * REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports.
     * Valid types include pairwise and public.
     */
    private array $subjectTypesSupported;

    /**
     * @var array
     * REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP
     * for the ID Token to encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be included.
     * The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token
     * from the Authorization Endpoint (such as when using the Authorization Code Flow).
     */
    private array $idTokenSigningAlgValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP
     * for the ID Token to encode the Claims in a JWT [JWT].
     */
    private array $idTokenEncryptionAlgValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP
     * for the ID Token to encode the Claims in a JWT [JWT].
     */
    private array $idTokenEncryptionEncValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported
     * by the UserInfo Endpoint to encode the Claims in a JWT [JWT]. The value none MAY be included.
     */
    private array $userinfoSigningAlgValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported
     * by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    private array $userinfoEncryptionAlgValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported
     * by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    private array $userinfoEncryptionEncValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported
     * by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core].
     * These algorithms are used both when the Request Object is passed by value (using the request parameter)
     * and when it is passed by reference (using the request_uri parameter). Servers SHOULD support none and RS256.
     */
    private array $requestObjectSigningAlgValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported
     * by the OP for Request Objects.
     * These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
     */
    private array $requestObjectEncryptionAlgValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP
     * for Request Objects.
     * These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
     */
    private array $requestObjectEncryptionEncValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
     * The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt,
     * as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core].
     * Other authentication methods MAY be defined by extensions. If omitted, the default is client_secret_basic --
     * the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
     */
    private array $tokenEndpointAuthMethodsSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported
     * by the Token Endpoint for the signature on the JWT [JWT] used to authenticate the Client at the Token Endpoint
     * for the private_key_jwt and client_secret_jwt authentication methods. Servers SHOULD support RS256.
     * The value none MUST NOT be used.
     */
    private array $tokenEndpointAuthSigningAlgValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports.
     * These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
     */
    private array $displayValuesSupported;

    /**
     * @var array
     * OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports.
     * These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core].
     * Values defined by this specification are normal, aggregated, and distributed.
     * If omitted, the implementation supports only normal Claims.
     */
    private array $claimTypesSupported;

    /**
     * @var array
     * RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY
     * be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
     */
    private array $claimsSupported;

    /**
     * @var string
     * OPTIONAL. URL of a page containing human-readable information that developers might want or need to know
     * when using the OpenID Provider. In particular, if the OpenID Provider does not support
     * Dynamic Client Registration,
     * then information on how to register Clients needs to be provided in this documentation.
     */
    private string $serviceDocumentation;

    /**
     * @var array
     * OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array
     * of BCP47 [RFC5646] language tag values.
     * Not all languages and scripts are necessarily supported for all Claim values.
     */
    private array $claimsLocalesSupported;

    /**
     * @var array
     * OPTIONAL. Languages and scripts supported for the user interface,
     * represented as a JSON array of BCP47 [RFC5646] language tag values.
     */
    private array $uiLocalesSupported;

    /**
     * @var bool
     * OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter,
     * with true indicating support. If omitted, the default value is false.
     */
    private bool $claimsParameterSupported;

    /**
     * @var bool
     * OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter,
     * with true indicating support.
     * If omitted, the default value is false.
     */
    private bool $requestParameterSupported;

    /**
     * @var bool
     * OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter,
     * with true indicating support.
     * If omitted, the default value is true.
     */
    private bool $requestUriParameterSupported;

    /**
     * @var bool
     * OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered
     * using the request_uris registration parameter. Pre-registration is REQUIRED when the value is true.
     * If omitted, the default value is false.
     */
    private bool $requireRequestUriRegistration;

    /**
     * @var string
     * OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read
     * about the OP's requirements on how the Relying Party can use the data provided by the OP.
     * The registration process SHOULD display this URL to the person registering the Client if it is given.
     */
    private string $opPolicyUri;

    /**
     * @var string
     * OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read
     * about OpenID Provider's terms of service.
     * The registration process SHOULD display this URL to the person registering the Client if it is given.
     */
    private string $opTosUri;

    /**
     * @throws GuzzleException
     */
    public static function create(string $discoverUri): self
    {
        $uri = sprintf('%s%s', rtrim($discoverUri, '/'), self::CONFIG_LOCATION);
        $response = (new HttpClient())->request('GET', $uri);

        $serializer = new Serializer([new ObjectNormalizer()], [new JsonEncoder()]);

        return $serializer->deserialize($response->getBody()->getContents(), self::class, self::CONFIG_FORMAT);
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function setIssuer(string $issuer): self
    {
        $this->issuer = $issuer;

        return $this;
    }

    public function getAuthorizationEndpoint(): string
    {
        return $this->authorizationEndpoint;
    }

    public function setAuthorizationEndpoint(string $authorizationEndpoint): self
    {
        $this->authorizationEndpoint = $authorizationEndpoint;

        return $this;
    }

    public function getTokenEndpoint(): string
    {
        return $this->tokenEndpoint;
    }

    public function setTokenEndpoint(string $tokenEndpoint): self
    {
        $this->tokenEndpoint = $tokenEndpoint;

        return $this;
    }

    public function getEndSessionEndpoint(): string
    {
        return $this->endSessionEndpoint;
    }

    public function setEndSessionEndpoint($endSessionEndpoint): void
    {
        $this->endSessionEndpoint = $endSessionEndpoint;
    }

    public function getUserinfoEndpoint(): string
    {
        return $this->userinfoEndpoint;
    }

    public function setUserinfoEndpoint(string $userinfoEndpoint): self
    {
        $this->userinfoEndpoint = $userinfoEndpoint;

        return $this;
    }

    public function getJwksUri(): string
    {
        return $this->jwksUri;
    }

    public function setJwksUri(string $jwksUri): self
    {
        $this->jwksUri = $jwksUri;

        return $this;
    }

    public function getRegistrationEndpoint(): string
    {
        return $this->registrationEndpoint;
    }

    public function setRegistrationEndpoint(string $registrationEndpoint): self
    {
        $this->registrationEndpoint = $registrationEndpoint;

        return $this;
    }

    public function getScopesSupported(): array
    {
        return $this->scopesSupported;
    }

    public function setScopesSupported(array $scopesSupported): self
    {
        $this->scopesSupported = $scopesSupported;

        return $this;
    }

    public function getResponseTypesSupported(): array
    {
        return $this->responseTypesSupported;
    }

    public function setResponseTypesSupported(array $responseTypesSupported): self
    {
        $this->responseTypesSupported = $responseTypesSupported;

        return $this;
    }

    public function getResponseModesSupported(): array
    {
        return $this->responseModesSupported;
    }

    public function setResponseModesSupported(array $responseModesSupported): self
    {
        $this->responseModesSupported = $responseModesSupported;

        return $this;
    }

    public function getGrantTypesSupported(): array
    {
        return $this->grantTypesSupported;
    }

    public function setGrantTypesSupported(array $grantTypesSupported): self
    {
        $this->grantTypesSupported = $grantTypesSupported;

        return $this;
    }

    public function getAcrValuesSupported(): array
    {
        return $this->acrValuesSupported;
    }

    public function setAcrValuesSupported(array $acrValuesSupported): self
    {
        $this->acrValuesSupported = $acrValuesSupported;

        return $this;
    }

    public function getSubjectTypesSupported(): array
    {
        return $this->subjectTypesSupported;
    }

    public function setSubjectTypesSupported(array $subjectTypesSupported): self
    {
        $this->subjectTypesSupported = $subjectTypesSupported;

        return $this;
    }

    public function getIdTokenSigningAlgValuesSupported(): array
    {
        return $this->idTokenSigningAlgValuesSupported;
    }

    public function setIdTokenSigningAlgValuesSupported(array $idTokenSigningAlgValuesSupported): self
    {
        $this->idTokenSigningAlgValuesSupported = $idTokenSigningAlgValuesSupported;

        return $this;
    }

    public function getIdTokenEncryptionAlgValuesSupported(): array
    {
        return $this->idTokenEncryptionAlgValuesSupported;
    }

    public function setIdTokenEncryptionAlgValuesSupported(array $idTokenEncryptionAlgValuesSupported): self
    {
        $this->idTokenEncryptionAlgValuesSupported = $idTokenEncryptionAlgValuesSupported;

        return $this;
    }

    public function getIdTokenEncryptionEncValuesSupported(): array
    {
        return $this->idTokenEncryptionEncValuesSupported;
    }

    public function setIdTokenEncryptionEncValuesSupported(array $idTokenEncryptionEncValuesSupported): self
    {
        $this->idTokenEncryptionEncValuesSupported = $idTokenEncryptionEncValuesSupported;

        return $this;
    }

    public function getUserinfoSigningAlgValuesSupported(): array
    {
        return $this->userinfoSigningAlgValuesSupported;
    }

    public function setUserinfoSigningAlgValuesSupported(array $userinfoSigningAlgValuesSupported): self
    {
        $this->userinfoSigningAlgValuesSupported = $userinfoSigningAlgValuesSupported;

        return $this;
    }

    public function getUserinfoEncryptionAlgValuesSupported(): array
    {
        return $this->userinfoEncryptionAlgValuesSupported;
    }

    public function setUserinfoEncryptionAlgValuesSupported(array $userinfoEncryptionAlgValuesSupported): self
    {
        $this->userinfoEncryptionAlgValuesSupported = $userinfoEncryptionAlgValuesSupported;

        return $this;
    }

    public function getUserinfoEncryptionEncValuesSupported(): array
    {
        return $this->userinfoEncryptionEncValuesSupported;
    }

    public function setUserinfoEncryptionEncValuesSupported(array $userinfoEncryptionEncValuesSupported): self
    {
        $this->userinfoEncryptionEncValuesSupported = $userinfoEncryptionEncValuesSupported;

        return $this;
    }

    public function getRequestObjectSigningAlgValuesSupported(): array
    {
        return $this->requestObjectSigningAlgValuesSupported;
    }

    public function setRequestObjectSigningAlgValuesSupported(array $requestObjectSigningAlgValuesSupported): self
    {
        $this->requestObjectSigningAlgValuesSupported = $requestObjectSigningAlgValuesSupported;

        return $this;
    }

    public function getRequestObjectEncryptionAlgValuesSupported(): array
    {
        return $this->requestObjectEncryptionAlgValuesSupported;
    }

    public function setRequestObjectEncryptionAlgValuesSupported(array $requestObjectEncryptionAlgValuesSupported): self
    {
        $this->requestObjectEncryptionAlgValuesSupported = $requestObjectEncryptionAlgValuesSupported;

        return $this;
    }

    public function getRequestObjectEncryptionEncValuesSupported(): array
    {
        return $this->requestObjectEncryptionEncValuesSupported;
    }

    public function setRequestObjectEncryptionEncValuesSupported(array $requestObjectEncryptionEncValuesSupported): self
    {
        $this->requestObjectEncryptionEncValuesSupported = $requestObjectEncryptionEncValuesSupported;

        return $this;
    }

    public function hasTokenEndpointAuthMethodSupport(string $method): bool
    {
        return in_array($method, $this->tokenEndpointAuthMethodsSupported, true);
    }

    public function getTokenEndpointAuthMethodsSupported(): array
    {
        return $this->tokenEndpointAuthMethodsSupported;
    }

    public function setTokenEndpointAuthMethodsSupported(array $tokenEndpointAuthMethodsSupported): self
    {
        $this->tokenEndpointAuthMethodsSupported = $tokenEndpointAuthMethodsSupported;

        return $this;
    }

    public function getTokenEndpointAuthSigningAlgValuesSupported(): array
    {
        return $this->tokenEndpointAuthSigningAlgValuesSupported;
    }

    public function setTokenEndpointAuthSigningAlgValuesSupported(
        array $tokenEndpointAuthSigningAlgValuesSupported
    ): self {
        $this->tokenEndpointAuthSigningAlgValuesSupported = $tokenEndpointAuthSigningAlgValuesSupported;

        return $this;
    }

    public function getDisplayValuesSupported(): array
    {
        return $this->displayValuesSupported;
    }

    public function setDisplayValuesSupported(array $displayValuesSupported): self
    {
        $this->displayValuesSupported = $displayValuesSupported;

        return $this;
    }

    public function getClaimTypesSupported(): array
    {
        return $this->claimTypesSupported;
    }

    public function setClaimTypesSupported(array $claimTypesSupported): self
    {
        $this->claimTypesSupported = $claimTypesSupported;

        return $this;
    }

    public function getClaimsSupported(): array
    {
        return $this->claimsSupported;
    }

    public function setClaimsSupported(array $claimsSupported): self
    {
        $this->claimsSupported = $claimsSupported;

        return $this;
    }

    public function getServiceDocumentation(): string
    {
        return $this->serviceDocumentation;
    }

    public function setServiceDocumentation(string $serviceDocumentation): self
    {
        $this->serviceDocumentation = $serviceDocumentation;

        return $this;
    }

    public function getClaimsLocalesSupported(): array
    {
        return $this->claimsLocalesSupported;
    }

    public function setClaimsLocalesSupported(array $claimsLocalesSupported): self
    {
        $this->claimsLocalesSupported = $claimsLocalesSupported;

        return $this;
    }

    public function getUiLocalesSupported(): array
    {
        return $this->uiLocalesSupported;
    }

    public function setUiLocalesSupported(array $uiLocalesSupported): self
    {
        $this->uiLocalesSupported = $uiLocalesSupported;

        return $this;
    }

    public function isClaimsParameterSupported(): bool
    {
        return $this->claimsParameterSupported;
    }

    public function setClaimsParameterSupported(bool $claimsParameterSupported): self
    {
        $this->claimsParameterSupported = $claimsParameterSupported;

        return $this;
    }

    public function isRequestParameterSupported(): bool
    {
        return $this->requestParameterSupported;
    }

    public function setRequestParameterSupported(bool $requestParameterSupported): self
    {
        $this->requestParameterSupported = $requestParameterSupported;

        return $this;
    }

    public function isRequestUriParameterSupported(): bool
    {
        return $this->requestUriParameterSupported;
    }

    public function setRequestUriParameterSupported(bool $requestUriParameterSupported): self
    {
        $this->requestUriParameterSupported = $requestUriParameterSupported;

        return $this;
    }

    public function isRequireRequestUriRegistration(): bool
    {
        return $this->requireRequestUriRegistration;
    }

    public function setRequireRequestUriRegistration(bool $requireRequestUriRegistration): self
    {
        $this->requireRequestUriRegistration = $requireRequestUriRegistration;

        return $this;
    }

    public function getOpPolicyUri(): string
    {
        return $this->opPolicyUri;
    }

    public function setOpPolicyUri(string $opPolicyUri): self
    {
        $this->opPolicyUri = $opPolicyUri;

        return $this;
    }

    public function getOpTosUri(): string
    {
        return $this->opTosUri;
    }

    public function setOpTosUri(string $opTosUri): self
    {
        $this->opTosUri = $opTosUri;

        return $this;
    }
}
