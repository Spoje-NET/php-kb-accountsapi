<?php

namespace KbApi;

use RuntimeException;
use SplFileInfo;

use function array_map;
use function is_numeric;
use function is_string;
use function preg_match;
use function preg_replace_callback;
use function rtrim;
use function str_starts_with;
use function strtolower;
use function trim;

/**
 * @property-read bool|null $SANDBOX
 * @property-read string|null $CERTIFICATE_PATH
 * @property-read string $ADAA_API_KEY
 * @property-read string $AUTH_API_KEY
 * @property-read string $AUTH_CALLBACK_URI
 * @property-read string $SOFT_REGISTRATION_API_KEY
 * @property-read string $SOFT_REGISTRATION_CALLBACK_URI
 * @property-read string $APP_REGISTRATION_API_KEY
 * @property-read string $APP_REGISTRATION_CALLBACK_URI
 */
class DotEnv
{
  private const VariableRegex = '[a-zA-Z_]+[a-zA-Z0-9_]*';


  /** @var array<string, string|int|float|bool|null>|null $variables */
  private ?array $variables = null;


  public function __construct(
    private readonly SplFileInfo $filePath,
  ) {
    $this->checkFilePath();
    $this->process();
  }


  public function __get(string $name): string|int|float|bool|null
  {
    if (!array_key_exists($name, $this->variables)) {
      throw new RuntimeException("Missing variable '{$name}'");
    }

    return $this->variables[$name];
  }


  private function process(): void
  {
    $file = $this->filePath->openFile();

    foreach ($file as $line) {
      $line = isset($multilineVariable) ? rtrim($line) : trim($line);

      if ($line === '') {
        continue;
      }

      // skips line with comment
      if (str_starts_with($line, '#')) {
        continue;
      }

      // splits the line to variable and value
      [$variable, $value] = array_map('trim', explode('=', $line, 2));

      if (preg_match('~^' . self::VariableRegex . '$~', $variable) === 0) {
        throw new RuntimeException("Wrong format of variable '{$variable}'");
      }

      // removes quotation marks and comment
      $valueMatches = [];
      preg_match('~^([^"\'][^#\s]+)|(["\'])([^\2]*)\2~', $value, $valueMatches);
      $value = $valueMatches[3] ?? $valueMatches[1] ?? null;

      $this->setVariable($variable, $value);
    }

    $this->variables = array_map(
      callback: fn ($val) => is_string($val) ? $this->interpolate($val) : $val,
      array: $this->variables
    );
  }


  private function checkFilePath(): void
  {
    if (!$this->filePath->isFile()) {
      throw new RuntimeException("Missing config file '{$this->filePath}'");
    }
    if (!$this->filePath->isReadable()) {
      throw new RuntimeException("Not readable config file '{$this->filePath}'");
    }
  }


  private function setVariable(string $name, ?string $value): void
  {
    $value = match (true) {
      $value === '', $value === null => null,
      is_numeric($value) => (int)$value === (float)$value ? (int)$value : (float)$value,
      in_array(strtolower($value), ['yes', 'true'], true) => true,
      in_array(strtolower($value), ['no', 'false'], true) => false,
      default => $value,
    };

    $this->variables[$name] = $value;
  }


  private function interpolate(string $value): string
  {
    return preg_replace_callback(
      pattern: '~\$\{(' . self::VariableRegex . ')}~',
      callback: fn (array $m): string => $this->variables[$m[1]] ?? throw new RuntimeException("Missing variable {$m[1]}"),
      subject: $value
    );
  }
}
