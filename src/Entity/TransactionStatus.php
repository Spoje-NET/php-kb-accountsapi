<?php

namespace Spojenet\KbAccountsApi\Entity;

enum TransactionStatus: string
{
  case Posted = 'BOOK';
  case Blocked = 'PNG';
}
