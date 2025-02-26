<?php

namespace Spojenet\KbAccountsApi\Entity;

class Tokens
{
  public function __construct(
    public Token $refresh,
    public Token $access,
  ) {
  }
}
