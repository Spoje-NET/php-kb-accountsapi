<?php

namespace SpojeNet\KbAccountsApi\Entity;

/**
 * @template T
 */
abstract class PageSlice
{
  /**
   * @param T[] $content
   */
  public function __construct(
    public readonly array $content,
    public readonly int $totalPages,
    public readonly int $pageNumber,
    public readonly int $pageSize,
    public readonly bool $numberOfElements,
    public readonly int $first,
    public readonly bool $last,
    public readonly bool $empty,
  ) {
  }
}
