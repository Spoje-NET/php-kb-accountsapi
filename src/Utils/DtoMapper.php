<?php

namespace SpojeNet\KbAccountsApi\Utils;

use ReflectionClass;
use ReflectionException;
use ReflectionNamedType;
use ReflectionParameter;
use RuntimeException;

use function array_key_exists;
use function enum_exists;
use function preg_match;

/**
 * @template T
 */
class DtoMapper
{
  /** @var array<class-string<T>, ReflectionParameter[]> */
  private static array $reflections = [];

  /** @var array<class-string, string> */
  private static array $genericTypes = [];


  /**
   * @param class-string<T> $class
   * @param array<string, mixed> $data
   * @throws RuntimeException|ReflectionException
   * @return T
   */
  public static function map(string $class, array $data): object
  {
    if (!isset(self::$reflections[$class])) {
      $reflection = new ReflectionClass($class);

      self::$reflections[$class] = $reflection->getConstructor()->getParameters();

      $docComment = $reflection->getDocComment();

      if ($docComment !== false && preg_match('~@extends\s+\w+<([^>]+)>~', $docComment, $matches)) {
        self::$genericTypes[$class] = "{$reflection->getNamespaceName()}\\{$matches[1]}";
      }
    }

    $args = [];

    foreach (self::$reflections[$class] as $parameter) {
      $name = $parameter->getName();
      $type = $parameter->getType();

      if (array_key_exists($name, $data)) {
        $value = $data[$name];
      } else {
        $args[$name] = match (true) {
          $parameter->isOptional() => $parameter->getDefaultValue(),
          $parameter->allowsNull() => null,
          default => throw new RuntimeException("Missing value for required parameter '{$class}::\${$name}'"),
        };

        continue;
      }

      if ($type instanceof ReflectionNamedType) {
        if (!$type->isBuiltin()) {
          $typeName = $type->getName();
          $value = enum_exists($typeName)
            ? $typeName::from($value)
            : self::map($typeName, (array)$value);

        } elseif ($type->getName() === 'array') {
          $docComment = $parameter->getDeclaringFunction()->getDocComment();

          if ($docComment !== false && preg_match('~@param\s+([^[\s]+)\[]\s+\$' . $name . '~', $docComment, $matches)) {
            $itemType = $matches[1];

            if ($itemType === 'T' && isset(self::$genericTypes[$class])) {
              $itemType = self::$genericTypes[$class];
            }

            $value = array_map(
              static fn (array $item) => self::map($itemType, (array)$item),
              $value
            );
          }
        }
      }

      $args[$name] = $value;
    }

    return new $class(...$args);
  }
}
