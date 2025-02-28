<?php

namespace SpojeNet\KbAccountsApi\Entity;

class Transaction
{
  public function __construct(
    public readonly \DateTimeImmutable $lastUpdated,
    public readonly TransactionAccountType $accountType,
    public readonly ?string $entryReference,
    public readonly string $iban,
    public readonly CreditDebit $creditDebitIndicator,
    public readonly TransactionType $transactionType,
    public readonly BankTransactionCode $bankTransactionCode,
    public readonly Amount $amount,
    public readonly ?\DateTimeImmutable $bookingDate,
    public readonly ?\DateTimeImmutable $valueDate,
    public readonly ?Amount $instructed,
    public readonly ?bool $reversalIndicator,
    public readonly ?TransactionStatus $status,
    public readonly ?TransactionCounterParty $counterParty,
    public readonly ?TransactionReferences $references,
    public readonly ?string $additionalTransactionInformation,
    public readonly ?TransactionCardDetails $cardTransactionDetails,
  ) {
  }
}
