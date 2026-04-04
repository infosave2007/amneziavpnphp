<?php
class Router {
  private static array $routes = [];

  public static function add(string $method, string $pattern, callable $handler): void {
    self::$routes[] = [
      'method' => strtoupper($method),
      'pattern' => self::normalizePattern($pattern),
      'handler' => $handler,
    ];
  }
  public static function get(string $pattern, callable $handler): void { self::add('GET', $pattern, $handler); }
  public static function post(string $pattern, callable $handler): void { self::add('POST', $pattern, $handler); }
  public static function put(string $pattern, callable $handler): void { self::add('PUT', $pattern, $handler); }
  public static function delete(string $pattern, callable $handler): void { self::add('DELETE', $pattern, $handler); }

  private static function normalizePattern(string $pattern): string {
    $pattern = '/' . trim($pattern, '/');
    $pattern = preg_replace('#\{([a-zA-Z_][a-zA-Z0-9_]*)\}#', '(?P<$1>[^/]+)', $pattern);
    return '#^' . $pattern . '$#';
  }

  public static function dispatch(string $method, string $uri): void {
    $path = parse_url($uri, PHP_URL_PATH) ?: '/';
    $path = '/' . trim($path, '/');
    foreach (self::$routes as $route) {
      if ($route['method'] !== strtoupper($method)) continue;
      if (preg_match($route['pattern'], $path, $matches)) {
        $params = [];
        foreach ($matches as $k => $v) { if (!is_int($k)) $params[$k] = $v; }
        call_user_func($route['handler'], $params);
        return;
      }
    }
    http_response_code(404);
    echo '404 Not Found';
  }
}