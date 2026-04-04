<?php
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;
use Twig\TwigFilter;

class View {
  private static ?Environment $twig = null;

  public static function init(string $templatesPath, array $globals = []): void {
    if (!class_exists(Environment::class)) {
      throw new RuntimeException('Twig is not installed. Run composer require twig/twig');
    }
    $loader = new FilesystemLoader($templatesPath);
    self::$twig = new Environment($loader, [
      'cache' => false,
      'autoescape' => 'html',
    ]);

    // Add translation function
    $tFunc = new TwigFunction('t', function (string $key, array $params = []) {
      return Translator::t($key, $params);
    });
    self::$twig->addFunction($tFunc);

    // Add flag emoji function
    $flagFunc = new TwigFunction('getFlag', function (string $langCode) {
      $flags = [
        'en' => '🇬🇧',
        'ru' => '🇷🇺',
        'es' => '🇪🇸',
        'de' => '🇩🇪',
        'fr' => '🇫🇷',
        'zh' => '🇨🇳',
      ];
      return $flags[$langCode] ?? '🌐';
    });
    self::$twig->addFunction($flagFunc);

    // Add bytes format filter
    $bytesFilter = new TwigFilter('bytes_format', function (int $bytes, int $precision = 2): string {
      $units = ['B', 'KB', 'MB', 'GB', 'TB'];
      for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
      }
      return round($bytes, $precision) . ' ' . $units[$i];
    });
    self::$twig->addFilter($bytesFilter);

    // Add translation filter (alias: trans)
    $transFilter = new TwigFilter('trans', function (string $key, array $params = []) {
      return Translator::t($key, $params);
    });
    self::$twig->addFilter($transFilter);

    // Add globals
    foreach ($globals as $k => $v) self::$twig->addGlobal($k, $v);
  }

  public static function render(string $template, array $vars = []): void {
    if (!self::$twig) throw new RuntimeException('Twig is not initialized');
    echo self::$twig->render($template, $vars);
  }
}