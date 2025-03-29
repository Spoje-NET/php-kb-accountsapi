<?php

namespace SpojeNet\KbAccountsApi\Entity;

class Balance
{
  public function __construct(
    public readonly BalanceType $type,
    public readonly Amount $amount,
    public readonly CreditDebit $creditDebitIndicator,
    public readonly \DateTimeImmutable $validAt,
  ) {
  }
}
