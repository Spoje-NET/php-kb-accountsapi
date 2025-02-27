<?php

namespace SpojeNet\KbAccountsApi\Entity;

use DateTimeImmutable;
use DateTimeInterface;

class Token
{
  public function __construct(
    public readonly string $token,
    public readonly DateTimeInterface $expiresAt,
  ) {
  }


  public function isValid(): bool
  {
    return $this->expiresAt->getTimestamp() > (new DateTimeImmutable())->getTimestamp();
  }
}
