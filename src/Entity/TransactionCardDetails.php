<?php

namespace SpojeNet\KbAccountsApi\Entity;

class TransactionCardDetails
{
  public function __construct(
    public readonly ?\DateTimeImmutable $holdExpirationDate,
  ) {
  }
}
