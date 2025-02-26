<?php

namespace Spojenet\KbAccountsApi\Entity;

class ClientReq
{
  public function __construct(
    public readonly string $name,
    public readonly string $type,
    public readonly string $encryptionKey,
    public readonly ?string $nameEN = null,
    public readonly array $scope = ['adaa'],
  ) {
  }
}
