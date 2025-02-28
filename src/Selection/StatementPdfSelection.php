<?php

namespace SpojeNet\KbAccountsApi\Selection;

class StatementPdfSelection
{
  public function __construct(
    public readonly string $accountId,
    public readonly int $statementId,
  ) {
  }
}
