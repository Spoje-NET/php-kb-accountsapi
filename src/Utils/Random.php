<?php

namespace SpojeNet\KbAccountsApi\Utils;

use function base64_encode;
use function bin2hex;
use function chr;
use function ord;
use function random_bytes;
use function str_split;
use function vsprintf;

class Random
{
  public static function encryptionKey(bool $forSandbox): string
  {
    /** Sandbox does not support custom encryption key, this specific key is required */
    return $forSandbox
      ? 'MnM1djh5L0I/RShIK01iUWVUaFdtWnEzdDZ3OXokQyY='
      : base64_encode(bin2hex(random_bytes(16)));
  }


  public static function correlationId(): string
  {
    $data = random_bytes(16);

    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
  }


  public static function state(): string
  {
    return bin2hex(random_bytes(3));
  }
}
