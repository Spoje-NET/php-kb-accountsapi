<?php

namespace SpojeNet\KbAccountsApi\Entity;

class ClientRes
{
  public function __construct(
    public readonly string $clientId,
    public readonly string $clientSecret,
    public readonly string $apiKey,
  ) {
  }
}
