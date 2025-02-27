<?php

namespace SpojeNet\KbAccountsApi\Entity;

class Transactions
{
  public function __construct(
    public readonly int $totalPages,
    public readonly int $page,
    public readonly int $size,
    public readonly bool $first,
    public readonly bool $last,
    public readonly string $empty,
    public readonly int $totalItems,
    /** @var Transaction[] $items */
    public array $items = [],
  ) {
  }
}
