<?php

namespace SpojeNet\KbAccountsApi\Entity;

class ApplicationReq
{
  public function __construct(
    public readonly string $id,
    public readonly string $name,
    public readonly string $version,
    /** @var list<string> $contacts */
    public readonly array $contacts,
    public readonly ?string $nameEN = null,
    public readonly ?string $uri = null,
    public readonly ?string $logoUri = null,
    public readonly ?string $tosUri = null,
    public readonly ?string $policyUri = null,
  ) {
  }
}
