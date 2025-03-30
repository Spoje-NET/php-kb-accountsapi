<?php

namespace SpojeNet\KbAccountsApi\Selection;

use DateTimeInterface;

class TransactionSelection
{
  public function __construct(
    public readonly string $accountId,
    public readonly int $page = 0,
    public readonly int $size = 100,
    public readonly ?DateTimeInterface $fromDateTime = null,
    public readonly ?DateTimeInterface $toDateTime = null,
  ) {
  }
}
