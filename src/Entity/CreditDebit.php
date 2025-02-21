<?php

namespace KbApi\Entity;

enum CreditDebit: string
{
  case Credit = 'CREDIT';
  case Debit = 'DEBIT';
}
