<?php

namespace KbApi\Entity;

enum TransactionStatus: string
{
  case Posted = 'BOOK';
  case Blocked = 'PNG';
}
