<?php

namespace SpojeNet\KbAccountsApi\Entity;

enum CreditDebit: string
{
  case Credit = 'CREDIT';
  case Debit = 'DEBIT';
}
