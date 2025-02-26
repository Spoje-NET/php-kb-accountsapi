<?php

namespace Spojenet\KbAccountsApi\Entity;

enum TransactionType: string
{
  case Interest = 'INTEREST';
  case Fee = 'FEE';
  case Domestic = 'DOMESTIC';
  case Foreign = 'FOREIGN';
  case Sepa = 'SEPA';
  case Cash = 'CASH';
  case Card = 'CARD';
  case Other = 'OTHER';
}
