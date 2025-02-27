<?php

namespace SpojeNet\KbAccountsApi\Entity;

class Tokens
{
  public function __construct(
    public Token $refresh,
    public Token $access,
  ) {
  }
}
