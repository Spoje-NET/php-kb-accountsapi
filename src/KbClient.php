<?php

namespace SpojeNet\KbAccountsApi;

use DateTimeImmutable;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\RequestOptions;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SplFileInfo;
use SpojeNet\KbAccountsApi\Entity\Account;
use SpojeNet\KbAccountsApi\Entity\ApplicationReq;
use SpojeNet\KbAccountsApi\Entity\ClientReq;
use SpojeNet\KbAccountsApi\Entity\ClientRes;
use SpojeNet\KbAccountsApi\Entity\Token;
use SpojeNet\KbAccountsApi\Entity\Tokens;
use SpojeNet\KbAccountsApi\Entity\Transactions;
use SpojeNet\KbAccountsApi\Entity\TransactionSelection;
use SpojeNet\KbAccountsApi\Exception\KbClientException;
use SpojeNet\KbAccountsApi\Utils\DtoMapper;
use SpojeNet\KbAccountsApi\Utils\Random;

use function array_filter;
use function array_unique;
use function base64_decode;
use function base64_encode;
use function compact;
use function http_build_query;
use function json_decode;
use function json_encode;
use function str_ends_with;
use function str_replace;
use function str_starts_with;
use function substr;

class KbClient
{
  public const RefreshTokenExpiration = '+12 months';


  public function __construct(
    public readonly Config $config,
    private readonly ClientInterface $httpClient,
    private readonly RequestFactoryInterface $requestFactory,
    private readonly StreamFactoryInterface $streamFactory,
  ) {
  }


  public static function createDefault(string $envFilePath): self
  {
    $config = Config::createFromEnv(new SplFileInfo($envFilePath));
    $clientOptions = [];

    if ($config->certificatePath) {
      $certificatePath = new SplFileInfo($config->certificatePath);

      if (!$certificatePath->isFile() || !$certificatePath->isReadable()) {
        throw new KbClientException('Certificate file not exists or is not readable', compact('config', 'certificatePath'));
      }

      $clientOptions[RequestOptions::CERT] = $certificatePath->getRealPath();
    }

    return new self(
      config: $config,
      httpClient: new Client($clientOptions),
      requestFactory: new HttpFactory(),
      streamFactory: new HttpFactory(),
    );
  }


  /**
   * Step 1
   * Registers the application via a software statement API
   *
   * @throws KbClientException
   * @return string JSON Web Token (JWT)
   */
  public function softwareStatement(ApplicationReq $application): string
  {
    if ($application->contacts === [] || count($application->contacts) > 2) {
      throw new KbClientException('At least one (max. 2) contact is required');
    }

    $body = $this->streamFactory->createStream(json_encode(array_filter([
      'softwareName' => $application->name,
      'softwareNameEn' => $application->nameEN,
      'softwareId' => $application->id,
      'softwareVersion' => $application->version,
      'softwareUri' => $application->uri,
      'contacts' => $application->contacts,
      'logoUri' => $application->logoUri,
      'tosUri' => $application->tosUri,
      'policyUri' => $application->policyUri,
      'redirectUris' => array_unique([
        $this->config->softRegistrationCallbackUri,
        $this->config->appRegistrationCallbackUri,
        $this->config->authCallbackUri,
      ]),
      'registrationBackUri' => $this->config->softRegistrationCallbackUri,
      'tokenEndpointAuthMethod' => 'client_secret_post',
      'grantTypes' => ['authorization_code', 'refresh_token'],
      'responseTypes' => ['code'],
    ])));

    $request = $this->requestFactory
      ->createRequest('POST', $this->config->softRegistrationUri)
      ->withHeader('X-Correlation-Id', Random::correlationId())
      ->withHeader('Content-Type', 'application/json')
      ->withHeader('apiKey', $this->config->softRegistrationApiKey)
      ->withBody($body);

    try {
      $response = $this->httpClient->sendRequest($request);
    } catch (ClientExceptionInterface $exc) {
      throw new KbClientException($exc->getMessage(), compact('body', 'request'), $exc);
    }

    $responseBody = $response->getBody()->getContents();

    if ($response->getStatusCode() !== 200) {
      $data = json_decode($responseBody, associative: true);

      throw new KbClientException($response->getReasonPhrase(), compact('response', 'data'));
    }

    return $responseBody;
  }


  /**
   * Step 2
   * URL for client's authorization of the application
   */
  public function clientAuthorizeRegistrationUri(string $appJwt, ClientReq $client, ?string $state = null): string
  {
    $data = base64_encode(json_encode(array_filter([
      'clientName' => $client->name,
      'clientNameEn' => $client->nameEN,
      'applicationType' => $client->type,
      'redirectUris' => [$this->config->appRegistrationCallbackUri],
      'scope' => $client->scope,
      'softwareStatement' => $appJwt,
      'encryptionAlg' => 'AES-256',
      'encryptionKey' => $client->encryptionKey,
    ])));

    return self::buildUri($this->config->appRegistrationUri, [
      'registrationRequest' => $data,
      'state' => $state ?? Random::state(),
    ]);
  }


  /**
   * Step 3
   * Decryption encrypted data from authorization's callback
   *
   * @throws KbClientException
   */
  public function decryptClientAuthorization(string $encryptionKey, string $salt, string $encryptedData): ClientRes
  {
    $encryptionKey = base64_decode($encryptionKey);
    $salt = self::base64UrlDecode($salt);
    $encryptedData = self::base64UrlDecode($encryptedData);

    $authenticationTagLength = 16;

    $dataBytes = substr($encryptedData, 0, -$authenticationTagLength);
    $authenticationTagBytes = substr($encryptedData, -$authenticationTagLength);

    $jsonData = openssl_decrypt(
      data: $dataBytes,
      cipher_algo: 'AES-256-GCM',
      passphrase: $encryptionKey,
      options: OPENSSL_RAW_DATA,
      iv: $salt,
      tag: $authenticationTagBytes,
    );

    if ($jsonData === false) {
      throw new KbClientException(
        'Failed to decrypt data',
        compact('encryptionKey', 'salt', 'encryptedData', 'dataBytes', 'authenticationTagBytes'),
      );
    }

    if (!str_starts_with($jsonData, '{') || !str_ends_with($jsonData, '}')) {
      throw new KbClientException('Invalid JSON data', compact('jsonData'));
    }

    $data = json_decode($jsonData, associative: true);

    return new ClientRes(
      clientId: $data['client_id'],
      clientSecret: $data['client_secret'],
      apiKey: $data['api_key'],
    );
  }


  /**
   * Step 4
   * URL for client's authorization of the ADAA and others scopes
   */
  public function clientAuthorizationCodeUri(string $clientId, array $scope = ['adaa'], ?string $state = null): string
  {
    return self::buildUri($this->config->authLoginUri, [
      'response_type' => 'code',
      'client_id' => $clientId,
      'scope' => implode(' ', $scope),
      'redirect_uri' => $this->config->authCallbackUri,
      'state' => $state ?? Random::state(),
    ]);
  }


  /**
   * Step 5
   * Gets refresh and access tokens by code from authorization's scopes
   *
   * @throws KbClientException
   */
  public function requestTokens(string $clientId, string $clientSecret, string $code): Tokens
  {
    $form = $this->streamFactory->createStream(self::formUrlEncode([
      'redirect_uri' => $this->config->authCallbackUri,
      'client_id' => $clientId,
      'client_secret' => $clientSecret,
      'code' => $code,
      'grant_type' => 'authorization_code',
    ]));

    $request = $this->requestFactory
      ->createRequest('POST', $this->config->authTokenUri)
      ->withHeader('X-Correlation-Id', Random::correlationId())
      ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
      ->withHeader('Accept', 'application/json')
      ->withHeader('apiKey', $this->config->authApiKey)
      ->withBody($form);

    try {
      $response = $this->httpClient->sendRequest($request);
    } catch (ClientExceptionInterface $exc) {
      throw new KbClientException($exc->getMessage(), compact('request', 'form'), $exc);
    }

    $responseBody = $response->getBody()->getContents();

    if ($response->getStatusCode() !== 200) {
      throw new KbClientException($response->getReasonPhrase(), compact('request', 'form', 'response', 'responseBody'));
    }

    $data = json_decode($responseBody, associative: true);

    return new Tokens(
      new Token($data['refresh_token'], new DateTimeImmutable(self::RefreshTokenExpiration)),
      new Token($data['access_token'], new DateTimeImmutable("+{$data['expires_in']} seconds")),
    );
  }


  /**
   * Step 6
   * Gets access token by refresh token
   *
   * @throws KbClientException
   */
  public function requestAccessToken(string $clientId, string $clientSecret, string $refreshToken): Token
  {
    $form = $this->streamFactory->createStream(http_build_query(dump([
      'redirect_uri' => $this->config->authCallbackUri,
      'client_id' => $clientId,
      'client_secret' => $clientSecret,
      'refresh_token' => $refreshToken,
      'grant_type' => 'refresh_token',
    ]), arg_separator: '&'));

    $request = $this->requestFactory
      ->createRequest('POST', $this->config->authTokenUri)
      ->withHeader('X-Correlation-Id', Random::correlationId())
      ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
      ->withHeader('apiKey', $this->config->authApiKey)
      ->withBody($form);

    try {
      $response = $this->httpClient->sendRequest($request);
    } catch (ClientExceptionInterface $exc) {
      throw new KbClientException($exc->getMessage(), compact('request'), $exc);
    }

    $responseBody = $response->getBody()->getContents();

    if ($response->getStatusCode() !== 200) {
      throw new KbClientException($response->getReasonPhrase(), compact('request', 'response', 'responseBody'));
    }

    $data = json_decode($responseBody, associative: true);

    return new Token($data['access_token'], new DateTimeImmutable("+{$data['expires_in']} seconds"));
  }


  /**
   * Step 7
   * Gets client's accounts
   *
   * @throws KbClientException
   * @return Account[]
   */
  public function accounts(string $accessToken): array
  {
    $data = $this->sendAdaaRequest($accessToken, '/accounts');

    return array_map(static fn (array $item) => DtoMapper::map(Account::class, $item), $data);
  }


  /* Other steps is just requested data for account like transactions */

  public function transactions(string $accessToken, TransactionSelection $selection): Transactions
  {
    $data = $this->sendAdaaRequest(
      accessToken: $accessToken,
      endpoint: "/accounts/{$selection->accountId}/transactions",
      params: array_filter([
        'page' => $selection->page,
        'size' => $selection->size,
        'fromDate' => $selection->fromDate?->format('Y-m-d'),
        'toDate' => $selection->toDate?->format('Y-m-d'),
      ], static fn ($value) => isset($value)),
    );

    return DtoMapper::map(Transactions::class, $data);
  }


  /* Utilities */

  /**
   * @param array<string, string> $params
   */
  private static function buildUri(string $uri, array $params): string
  {
    return $uri . ($params === [] ? '' : ('?' . http_build_query($params, arg_separator: '&')));
  }


  private static function base64UrlDecode(string $s): string
  {
    return base64_decode(str_replace(['-', '_'], ['+', '/'], $s));
  }


  private static function formUrlEncode(array $params): string
  {
    return http_build_query($params, arg_separator: '&');
  }


  /**
   * @throws KbClientException
   * @return mixed[]
   */
  private function sendAdaaRequest(string $accessToken, string $endpoint, array $params = []): array
  {
    $request = $this->requestFactory
      ->createRequest('GET', self::buildUri("{$this->config->adaaUri}{$endpoint}", $params))
      ->withHeader('X-Correlation-Id', Random::correlationId())
      ->withHeader('apiKey', $this->config->adaaApiKey)
      ->withHeader('Authorization', "Bearer {$accessToken}")
      ->withHeader('Accept', 'application/json');

    try {
      $response = $this->httpClient->sendRequest($request);
    } catch (ClientExceptionInterface $exc) {
      throw new KbClientException($exc->getMessage(), compact('request'), $exc);
    }

    $responseBody = $response->getBody()->getContents();

    if ($response->getStatusCode() !== 200) {
      throw new KbClientException($response->getReasonPhrase(), compact('request', 'response', 'responseBody'));
    }

    return json_decode($responseBody, associative: true);
  }
}
