<?php

namespace SpojeNet\KbAccountsApi\Entity;

class BankTransactionCode
{
  public function __construct(
    public readonly string $code,
    public readonly string $issuer,
  ) {
  }
}
