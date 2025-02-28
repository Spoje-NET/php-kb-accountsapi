<?php

namespace SpojeNet\KbAccountsApi\Entity;

class Account
{
  public function __construct(
    public readonly string $accountId,
    public readonly string $iban,
    public readonly string $currency,
  ) {
  }
}
