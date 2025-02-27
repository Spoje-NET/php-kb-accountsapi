<?php

namespace SpojeNet\KbAccountsApi\Entity;

use DateTimeImmutable;

class Transaction
{
  public function __construct(
    public readonly DateTimeImmutable $lastUpdated,
    public readonly ?DateTimeImmutable $bookingDate,
    public readonly CreditDebit $creditDebitIndicator,
    public readonly TransactionType $transactionType,
    public readonly ?TransactionStatus $status,
    public readonly string $counterPartyIban,
    public readonly string $counterPartyName,
    public readonly float $amountValue,
    public readonly string $currency,
    public readonly string $variable,
    public readonly string $constant,
    public readonly string $specific,
    public readonly string $note,
    public readonly string $additionalTransactionInformation,
  ) {
  }
}
