<?php

namespace SpojeNet\KbAccountsApi\Entity;

enum TransactionAccountType: string
{
  case KBAccounts = 'KB';
  case AggregateAccounts = 'AG';
}
