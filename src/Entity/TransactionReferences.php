<?php

namespace SpojeNet\KbAccountsApi\Entity;

class TransactionReferences
{
  public function __construct(
    public readonly ?string $accountServicer,
    public readonly ?string $endToEndIdentification,
    public readonly ?string $variable,
    public readonly ?string $constant,
    public readonly ?string $specific,
    public readonly ?string $receiver,
    public readonly ?string $myDescription,
  ) {
  }
}
