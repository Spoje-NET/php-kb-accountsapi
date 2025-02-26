<?php

namespace Spojenet\KbAccountsApi;

use SplFileInfo;

class Config
{
  private const SoftRegisterUriProd = 'https://client-registration.api-gateway.kb.cz/v3/software-statements';
  private const SoftRegisterUriSand = 'https://api-gateway.kb.cz/sandbox/client-registration/v3/software-statements';
  private const AppRegisterUriProd = 'https://api-gateway.kb.cz/client-registration-ui/v2/saml/register';
  private const AppRegisterUriSand = 'https://api-gateway.kb.cz/sandbox/client-registration-ui/v2/saml/register';
  private const AuthLoginUriProd = 'https://login.kb.cz/autfe/ssologin';
  private const AuthLoginUriSand = 'https://api-gateway.kb.cz/sandbox/oauth2-authorization-ui/v3/';
  private const AuthTokenUriProd = 'https://api-gateway.kb.cz/oauth2/v3/access_token';
  private const AuthTokenUriSand = 'https://api-gateway.kb.cz/sandbox/oauth2/v3/access_token';
  private const AdaaUriProd = 'https://api-gateway.kb.cz/adaa/v2';
  private const AdaaUriSand = 'https://api-gateway.kb.cz/sandbox/adaa/v2';

  public function __construct(
    public bool $sandbox,
    public ?string $certificatePath,
    public string $softRegistrationApiKey,
    public string $softRegistrationUri,
    public string $softRegistrationCallbackUri,
    public string $appRegistrationApiKey,
    public string $appRegistrationUri,
    public string $appRegistrationCallbackUri,
    public string $authApiKey,
    public string $authCallbackUri,
    public string $authLoginUri,
    public string $authTokenUri,
    public string $adaaApiKey,
    public string $adaaUri,
  ) {
  }


  public static function createFromEnv(SplFileInfo $filePath): self
  {
    $env = new DotEnv($filePath);
    $sandbox = $env->KB_ACCOUNTSAPI_SANDBOX ?? false;

    return new self(
      sandbox: $sandbox,
      certificatePath: $env->KB_ACCOUNTSAPI_CERTIFICATE_PATH,
      softRegistrationApiKey: $env->KB_ACCOUNTSAPI_SOFT_REGISTRATION_API_KEY,
      softRegistrationUri: $sandbox ? self::SoftRegisterUriSand : self::SoftRegisterUriProd,
      softRegistrationCallbackUri: $env->KB_ACCOUNTSAPI_SOFT_REGISTRATION_CALLBACK_URI,
      appRegistrationApiKey: $env->KB_ACCOUNTSAPI_APP_REGISTRATION_API_KEY,
      appRegistrationUri: $sandbox ? self::AppRegisterUriSand : self::AppRegisterUriProd,
      appRegistrationCallbackUri: $env->KB_ACCOUNTSAPI_APP_REGISTRATION_CALLBACK_URI,
      authApiKey: $env->KB_ACCOUNTSAPI_AUTH_API_KEY,
      authCallbackUri: $env->KB_ACCOUNTSAPI_AUTH_CALLBACK_URI,
      authLoginUri: $sandbox ? self::AuthLoginUriSand : self::AuthLoginUriProd,
      authTokenUri: $sandbox ? self::AuthTokenUriSand : self::AuthTokenUriProd,
      adaaApiKey: $env->KB_ACCOUNTSAPI_ADAA_API_KEY,
      adaaUri: $sandbox ? self::AdaaUriSand : self::AdaaUriProd,
    );
  }
}
