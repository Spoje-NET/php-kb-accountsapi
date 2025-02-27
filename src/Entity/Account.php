<?php

namespace SpojeNet\KbAccountsApi\Entity;

class Account
{
  public function __construct(
    public readonly string $id,
    public readonly string $iban,
    public readonly string $currencyCode,
  ) {
  }
}
