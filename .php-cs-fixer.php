<?php

$finder = PhpCsFixer\Finder::create()->in(__DIR__ . '/src');
$config = new PhpCsFixer\Config();

return $config->setRules([
  '@PSR12' => true,
  'phpdoc_order' => true,
  'array_syntax' => ['syntax' => 'short'],
  'strict_comparison' => true,
  'no_whitespace_in_blank_line' => true,
  'no_trailing_whitespace' => false,
  'no_trailing_whitespace_in_comment' => false,
  'braces' => false,
  'single_blank_line_at_eof' => true,
  'blank_line_after_namespace' => true,
  'blank_line_before_statement' => [
    'statements' => [
      'break',
      'continue',
      'declare',
      'default',
      'do',
      'exit',
      'for',
      'foreach',
      'goto',
      'if',
      'include',
      'include_once',
      'require',
      'require_once',
      'return',
      'switch',
      'throw',
      'try',
      'while',
    ],
  ]
])->setFinder($finder)
  ->setIndent('  ');
