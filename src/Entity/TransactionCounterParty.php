<?php

namespace SpojeNet\KbAccountsApi\Entity;

class TransactionCounterParty
{
  public function __construct(
    public readonly ?string $iban,
    public readonly ?string $name,
    public readonly ?string $accountNo,
    public readonly ?string $bankBic,
    public readonly ?string $bankCode,
    public readonly ?string $bankName,
  ) {
  }
}
