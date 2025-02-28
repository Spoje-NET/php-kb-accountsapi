<?php

namespace SpojeNet\KbAccountsApi\Entity;

class Amount
{
  public function __construct(
    public readonly float $value,
    public readonly string $currency
  ) {
  }
}
