<?php

namespace KbApi\Exception;

use Throwable;

class KbClientException extends \Exception
{
  public function __construct(
    string $message,
    /** @var array<string, mixed> [variable: value] */
    private array $context = [],
    ?Throwable $previous = null
  ) {
    parent::__construct($message, previous: $previous);
  }


  public function getContext(): array
  {
    return $this->context;
  }
}
