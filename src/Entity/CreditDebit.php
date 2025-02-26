<?php

namespace Spojenet\KbAccountsApi\Entity;

enum CreditDebit: string
{
  case Credit = 'CREDIT';
  case Debit = 'DEBIT';
}
