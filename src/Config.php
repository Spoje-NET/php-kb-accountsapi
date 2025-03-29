<?php

namespace SpojeNet\KbAccountsApi;

use SplFileInfo;
use SpojeNet\KbAccountsApi\Utils\DotEnv;

class Config
{
  protected const SoftRegisterUriProd = 'https://client-registration.api-gateway.kb.cz/v3/software-statements';
  protected const SoftRegisterUriSand = 'https://api-gateway.kb.cz/sandbox/client-registration/v3/software-statements';
  protected const AppRegisterUriProd = 'https://api-gateway.kb.cz/client-registration-ui/v2/saml/register';
  protected const AppRegisterUriSand = 'https://api-gateway.kb.cz/sandbox/client-registration-ui/v2/saml/register';
  protected const AuthLoginUriProd = 'https://login.kb.cz/autfe/ssologin';
  protected const AuthLoginUriSand = 'https://api-gateway.kb.cz/sandbox/oauth2-authorization-ui/v3/';
  protected const AuthTokenUriProd = 'https://api-gateway.kb.cz/oauth2/v3/access_token';
  protected const AuthTokenUriSand = 'https://api-gateway.kb.cz/sandbox/oauth2/v3/access_token';
  protected const AdaaUriProd = 'https://api-gateway.kb.cz/adaa/v2';
  protected const AdaaUriSand = 'https://api-gateway.kb.cz/sandbox/adaa/v2';


  private function __construct(
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


  public static function createFromDotEnv(SplFileInfo $filePath): self
  {
    $env = new DotEnv($filePath);
    $creator = ($env->KB_ACCOUNTSAPI_SANDBOX ?? false)
      ? self::createSandbox(...)
      : self::createProduction(...);

    return $creator(
      certificatePath: $env->KB_ACCOUNTSAPI_CERTIFICATE_PATH,
      softRegistrationApiKey: $env->KB_ACCOUNTSAPI_SOFT_REGISTRATION_API_KEY,
      softRegistrationCallbackUri: $env->KB_ACCOUNTSAPI_SOFT_REGISTRATION_CALLBACK_URI,
      appRegistrationApiKey: $env->KB_ACCOUNTSAPI_APP_REGISTRATION_API_KEY,
      appRegistrationCallbackUri: $env->KB_ACCOUNTSAPI_APP_REGISTRATION_CALLBACK_URI,
      authApiKey: $env->KB_ACCOUNTSAPI_AUTH_API_KEY,
      authCallbackUri: $env->KB_ACCOUNTSAPI_AUTH_CALLBACK_URI,
      adaaApiKey: $env->KB_ACCOUNTSAPI_ADAA_API_KEY,
    );
  }


  public static function createSandbox(
    ?string $certificatePath,
    string $softRegistrationApiKey,
    string $softRegistrationCallbackUri,
    string $appRegistrationApiKey,
    string $appRegistrationCallbackUri,
    string $authApiKey,
    string $authCallbackUri,
    string $adaaApiKey,
  ): self {
    return new self(
      sandbox: true,
      certificatePath: $certificatePath,
      softRegistrationApiKey: $softRegistrationApiKey,
      softRegistrationUri: self::SoftRegisterUriSand,
      softRegistrationCallbackUri: $softRegistrationCallbackUri,
      appRegistrationApiKey: $appRegistrationApiKey,
      appRegistrationUri: self::AppRegisterUriSand,
      appRegistrationCallbackUri: $appRegistrationCallbackUri,
      authApiKey: $authApiKey,
      authCallbackUri: $authCallbackUri,
      authLoginUri: self::AuthLoginUriSand,
      authTokenUri: self::AuthTokenUriSand,
      adaaApiKey: $adaaApiKey,
      adaaUri: self::AdaaUriSand,
    );
  }


  public static function createProduction(
    ?string $certificatePath,
    string $softRegistrationApiKey,
    string $softRegistrationCallbackUri,
    string $appRegistrationApiKey,
    string $appRegistrationCallbackUri,
    string $authApiKey,
    string $authCallbackUri,
    string $adaaApiKey,
  ): self {
    return new self(
      sandbox: false,
      certificatePath: $certificatePath,
      softRegistrationApiKey: $softRegistrationApiKey,
      softRegistrationUri: self::SoftRegisterUriProd,
      softRegistrationCallbackUri: $softRegistrationCallbackUri,
      appRegistrationApiKey: $appRegistrationApiKey,
      appRegistrationUri: self::AppRegisterUriProd,
      appRegistrationCallbackUri: $appRegistrationCallbackUri,
      authApiKey: $authApiKey,
      authCallbackUri: $authCallbackUri,
      authLoginUri: self::AuthLoginUriProd,
      authTokenUri: self::AuthTokenUriProd,
      adaaApiKey: $adaaApiKey,
      adaaUri: self::AdaaUriProd,
    );
  }
}
