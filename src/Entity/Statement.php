<?php

namespace SpojeNet\KbAccountsApi\Entity;

class Statement
{
  public function __construct(
    public readonly \DateTimeImmutable $issued,
    public readonly int $sequenceNumber,
    public readonly int $pagesCount,
    public readonly int $statementId,
    public readonly bool $archive,
  ) {
  }
}
