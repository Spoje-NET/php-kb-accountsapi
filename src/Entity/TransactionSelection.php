<?php

namespace KbApi\Entity;

use DateTimeInterface;

class TransactionSelection
{
  public function __construct(
    public readonly string $accountId,
    public readonly int $page = 0,
    public readonly int $size = 100,
    public readonly ?DateTimeInterface $fromDate = null,
    public readonly ?DateTimeInterface $toDate = null,
  ) {
  }
}
