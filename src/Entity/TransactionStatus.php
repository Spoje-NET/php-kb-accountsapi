<?php

namespace SpojeNet\KbAccountsApi\Entity;

enum TransactionStatus: string
{
  case Posted = 'BOOK';
  case Blocked = 'PNG';
}
