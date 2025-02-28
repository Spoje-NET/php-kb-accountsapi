<?php

namespace SpojeNet\KbAccountsApi\Selection;

use DateTimeImmutable;

class StatementsSelection
{
  public function __construct(
    public readonly string $accountId,
    public readonly DateTimeImmutable $dateFrom,
  ) {
  }
}
