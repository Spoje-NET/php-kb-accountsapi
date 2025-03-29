<?php

namespace SpojeNet\KbAccountsApi\Entity;

enum BalanceType: string
{
  /**
   * Opening balance of the day = closing balance of the previous day, i.e. day - 1.
   * Are only the booked transactions, what the day opens with, closed with the previous day's accounting.
   */
  case Opening = 'PREVIOUSLY_CLOSED_BOOK';

  /**
   * This type of balance is not used.
   */
  case Booked = 'CLOSING_BOOKED';

  /**
   * Includes everything, even unbooked transactions = current balance available to you.
   */
  case Available = 'CLOSING_AVAILABLE';
}
