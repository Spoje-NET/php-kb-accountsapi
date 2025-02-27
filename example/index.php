<?php
/**
 * From the root of the project in the command line, start the PHP dev server with the command:
 * php -S localhost:8000 -t example/
 */

use SpojeNet\KbAccountsApi\Entity\Tokens;
use SpojeNet\KbAccountsApi\Entity\ClientReq;
use SpojeNet\KbAccountsApi\Entity\ApplicationReq;
use SpojeNet\KbAccountsApi\Entity\TransactionSelection;
use SpojeNet\KbAccountsApi\Exception\KbClientException;
use SpojeNet\KbAccountsApi\KbClient;
use Tracy\Debugger;

require_once __DIR__ . '/../vendor/autoload.php';
Debugger::enable(Debugger::Development);

const AppID = 'sda-1';

$kbClient = KbClient::createDefault(__DIR__ . '/../example.env');


class Storage
{
  private ?Application $app;

  public function __construct(private readonly SplFileInfo $file)
  {
    $this->app = file_exists($this->file->getPathname())
      ? unserialize(file_get_contents($this->file->getPathname()) ?: 'N;')
      : null;
  }

  public function __destruct()
  {
    file_put_contents($this->file->getPathname(), serialize($this->app));
  }

  public function get(): ?Application
  {
    return $this->app;
  }

  public function set(?Application $value): void
  {
    $this->app = $value;
  }
}
$storage = new Storage(new SplFileInfo(__DIR__ . '/.storage'));

// Entities ***********************************************************************************************************

class Application
{
  public function __construct(
    public string $id,
    public string $name,
    public string $version,
    public ?string $jwt = null,
    public ?Client $client = null,
    public ?Tokens $tokens = null,
  ) {}
}

class Client
{
  public function __construct(
    public string $name,
    public string $type,
    public string $encryptionKey,
    public ?string $clientId = null,
    public ?string $clientSecret = null,
    public ?string $apiKey = null,
    public ?string $registrationClientUri = null,
  ) {}
}


// Utilities **********************************************************************************************************

function writeLabel(string $label): void
{
  static $level = 2;
  echo "<h{$level}>{$label}</h{$level}>";
  if ($level < 5) $level++;
}

function writeOutput($output): void
{
  echo is_string($output)
    ? "<pre>\n{$output}</pre>"
    : Debugger::dump($output, return: true);
}

function validateEncryptionKey(string $key): bool {
  return strlen($key) === 44 && strlen(base64_decode($key)) === 32;
}

function sanitizeInput(string $name): string
{
  $input = $_POST[$name] ?? $_GET[$name] ?? throw new RuntimeException("Missing input '{$name}'");
  $input = trim($input);
  $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');

  return strip_tags($input);
}

function short(?string $input): string {
  if ($input === null) return '';
  if (strlen($input) <= 40) return $input;
  return substr($input, 0, 20) . '…' . substr($input, -10);
}


// Router's handlers for page *****************************************************************************************

function home(): void
{
  global $storage;

  writeLabel('Application');
  $app = $storage->get();

  if ($app) {
    echo <<<HTML
      <table>
        <tr><th>ID</th><td>{$app->id}</td></tr>
        <tr><th>Name</th><td>{$app->name}</td></tr>
        <tr><th>Version</th><td>{$app->version}</td></tr>
        <tr><th></th><td><a href='/app'>detail</a></td></tr>
    </table>
    HTML;
  } else {
    writeLabel('New registration');
    echo <<<HTML
      <form method="post" action="/reg">
        <label for="softwareName">Application name</label>
        <input type="text" name="softwareName" id="softwareName" required value="Super Duper Application" />
        <label for="clientName">Client name</label>
        <input type="text" name="clientName" id="clientName" required value="Web app" />
        <input type="submit" value="Registration" />
      </form>
    HTML;
  }
}

function registration(): void
{
  global $storage, $kbClient;

  $app = new Application(
    id: AppID,
    name: sanitizeInput('softwareName'),
    version: '1.0',
    client: new Client(
      name: sanitizeInput('clientName'),
      type: 'web',
      encryptionKey: $kbClient::createEncryptionKey($kbClient->config->sandbox),
    ),
  );

  $jwt = $kbClient->softwareStatement(new ApplicationReq(
    id: $app->id,
    name: $app->name,
    version: $app->version,
    contacts: ['email: info@example.com'],
  ));

  $app->jwt = $jwt;
  $storage->set($app);

  writeLabel('Require a authorization');
  $url = $kbClient->clientAuthorizeRegistrationUri($app->jwt, new ClientReq(
    name: $app->client->name,
    type: $app->client->type,
    encryptionKey: $app->client->encryptionKey,
  ));
  echo '<a href="' . $url . '" target="_blank" rel="opener">authorize a registration</a>';
}

function application(): void
{
  global $kbClient, $storage;

  $app = $storage->get();

  if ($app === null) {
    writeLabel('Application not found');
    return;
  }

  writeLabel("Application {$app->name}");

  $apiKey = short($app->client->apiKey);
  $jwt = short($app->jwt);
  $encryptionKeyValid = validateEncryptionKey($app->client->encryptionKey) ? '✅' : '🚫';
  $clientIdLabel = $app->client->clientId;
  if ($clientIdLabel === null) {
    $uri = $kbClient->clientAuthorizeRegistrationUri($app->jwt, new ClientReq(
      name: $app->client->name,
      type: $app->client->type,
      encryptionKey: $app->client->encryptionKey,
    ), $app->id);
    $clientIdLabel = '<a href="' . $uri . '" target="_blank">authorize</a>';
  }

  $tokenLabel = 'Missing Client ID!';
  if(isset($app->tokens)) {
    $tokenLabel = short($app->tokens->refresh->token);
    $tokenLabel .= $app->tokens->refresh->isValid() ? ' ✅' : ' 🚫';
  } elseif (isset($app->client->clientId)) {
    $uri = $kbClient->clientAuthorizationCodeUri($app->client->clientId);
    $tokenLabel = '<a href="' . $uri . '" target="_blank">authorize</a>';
  }

  echo <<<HTML
    <table>
      <tr><th>Application ID</th><td>{$app->id}</td></tr>
      <tr><th>Application name</th><td>{$app->name}</td></tr>
      <tr><th>Application version</th><td>{$app->version}</td></tr>
      <tr><th>JWT</th><td>{$jwt}</td></tr>
      <tr><th>Client name</th><td>{$app->client->name}</td></tr>
      <tr><th>Client type</th><td>{$app->client->type}</td></tr>
      <tr><th>Encryption key</th><td>{$app->client->encryptionKey} {$encryptionKeyValid}</td></tr>
      <tr><th>Client ID</th><td>{$clientIdLabel}</td></tr>
      <tr><th>Client secret</th><td>{$app->client->clientSecret}</td></tr>
      <tr><th>API key</th><td>{$apiKey}</td></tr>
      <tr><th>Refresh token</th><td>{$tokenLabel}</td></tr>
      <tr><th></th><td><a href="/del">remove</a></td></tr>
    </table>
  HTML;

  if ($app->tokens === null) {
    return;
  }

  if ($app->tokens->access->isValid() === false) {
    $app->tokens->access = $kbClient->requestAccessToken($app->client->clientId, $app->client->clientSecret, $app->tokens->refresh->token);
  }

  writeLabel('Accounts');
  $accounts = $kbClient->accounts($app->tokens->access->token);

  echo <<<HTML
    <table>
      <tr><th>ID</th><th>IBAN</th><th>Currency</th></tr>
  HTML;
  $accountIdForTransactions = null;
  foreach ($accounts as $account) {
    $accountIdForTransactions ??= $account->id;
    $accountId = short($account->id);
    echo <<<HTML
      <tr><td>{$accountId}</td><td>{$account->iban}</td><td>{$account->currencyCode}</td></tr>
    HTML;
  }
  echo '</table>';

  writeLabel("Transactions for account ID {$accountIdForTransactions}");
  $transactions = $kbClient->transactions($app->tokens->access->token, new TransactionSelection($accountIdForTransactions));
  echo <<<HTML
    <table>
      <tr><th>Items:</th><td>{$transactions->totalItems}</td></tr>
      <tr><th>Pages:</th><td>{$transactions->totalPages}</td></tr>
    </table>
  HTML;
  array_walk($transactions->items, fn($item) => writeOutput($item));
}

function delete(): void {
  global $storage;

  $app = $storage->get();

  if (!$app) {
    writeLabel('Application not found');
    return;
  }

  $storage->set(null);

  writeLabel("Application {$app->name} deleted");
}

function callback(): void {
  global $storage, $kbClient;

  writeLabel('Callback request');
  writeOutput($_GET);

  $app = $storage->get() ?? throw new Exception('Application not found');

  /** Callback from client's authorization of registration */
  if (isset($_GET['encryptedData'])) {
    writeLabel('Application authorization');
    $response = $kbClient->decryptClientAuthorization($app->client->encryptionKey, $_GET['salt'], $_GET['encryptedData']);

    $app->client->clientId = $response->clientId;
    $app->client->clientSecret = $response->clientSecret;
    $app->client->apiKey = $response->apiKey;

    $storage->set($app);

    writeLabel('Authorized');
    $apiKey = short($app->client->apiKey);
    echo <<<HTML
      <table>
        <tr><th>Client ID</th><td>{$app->client->clientId}</td></tr>
        <tr><th>API key</th><td>{$apiKey}</td></tr>
      </table>
      <br />
      <button onclick="window.onbeforeunload = () => {window.opener.location.href = '/app'}; window.close()">app detail</button>
    HTML;
  }
  /** Callback from client's authorization of scope */
  elseif (isset($_GET['code'])) {
    writeLabel('Scope authorization');
    $tokens = $kbClient->requestTokens($app->client->clientId, $app->client->clientSecret, $_GET['code']);

    writeLabel('Authorized');
    $app->tokens = $tokens;
    $refreshToken = short($tokens->refresh->token);
    $accessToken = short($tokens->access->token);
    echo <<<HTML
      <table>
        <tr><th>Refresh token</th><td>{$refreshToken}</td></tr>
        <tr><th>Access token</th><td>{$accessToken}</td></tr>
      </table>
      <br />
      <button onclick="window.onbeforeunload = () => window.opener.location.reload(); window.close()">app detail</button>
    HTML;
  }
}

// Application logic **************************************************************************************************
function run(): void
{
  try {
    $path = $_SERVER['PATH_INFO'] ?? '/';
    $action = match ($path) {
      '/' => fn() => home(),
      '/reg' => fn() => registration(),
      '/app' => fn() => application(),
      '/del' => fn() => delete(),
      '/back' => fn() => callback(),
      default => null,
    };

    if (empty($action)) throw new RuntimeException("Action for path missing, given '{$path}'");

    $action();

  } catch (KbClientException $exc) {
    writeLabel($exc->getMessage());
    writeLabel('Context');
    writeOutput($exc->getContext());
    writeLabel('Trace');
    writeOutput($exc->getTrace());

  } catch (Throwable $exc) {
    $error = get_class($exc);
    writeLabel("{$error}: <small>{$exc->getMessage()}</small>");
    writeLabel('Trace');
    writeOutput($exc->getTrace());
  }
}

// HTML ***************************************************************************************************************
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>KB API</title>
  <link rel="icon" type="image/png" href="data:image/x-icon;base64,AAABAAMAICAAAAEAIAAoEQAANgAAABAQAAABACAAaAQAAF4RAAAQEAAAAQAgAGgEAADGFQAAKAAAACAAAABAAAAAAQAgAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAANgAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADpAAAA6QAAAOkAAADgAAAA7gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPcAAADuAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA9wAAAO4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD3AAAA7gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPcAAADuAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA9wAAAO4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD3AAAA7gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPcAAADuAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA9wAAAO4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD3AAAA7gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPcAAADuAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA9wAAAO4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD3AAAA7gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPcAAADuAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA9wAAAO4AAAD/AAAA/wAAAP8AAAD/Wlpa/+7v7//u7+//7u/v/+7v7//u7+//7u/v/+7v7//u7+//7u/v/+7v7//u7+//7u/v/+7v7//u7+//7u/v/+7v7//u7+//7u/v/+7v7//u7+//YmJi/wAAAP8AAAD/AAAA/wAAAP8AAAD3KADf5igA3vcoAN73KADe9ygA3vd7Y+v6/v////7////+/////v////7////+/////v////7////+/////v////7////+/////v////7////+/////v////7////+/////v////7///+EbO36KADe9ygA3vcoAN73KADe9ycA3u8pAObuKQDm/ykA5v8pAOb/KQDm/ykA5v8rAub/KwLm/ysC5v8rAub/KwLm/ysC5v8rAub/KwLm/ysC5v8rAub/KwLm/ysC5v8rAub/KwLm/ysC5v8rAub/KwLm/ysC5v8rAub/KwLm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm9ykA5u4pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb3KQDm7ikA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5vcpAObuKQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm9ykA5u4pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb3KQDm7ikA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5vcpAObuKQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm9ykA5u4pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb3KQDm7ikA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5vcpAObuKQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm9ykA5u4pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb3KQDm7ikA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5vcpAObuKQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm9ykA5u4pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb3KQDm6ikA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vwpAOb8KQDm/CkA5vMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAABAAAAAgAAAAAQAgAAAAAAAABAAAEwsAABMLAAAAAAAAAAAAAAAAAOsAAAD1AAAA8wAAAPQAAADzAAAA9AAAAPQAAAD0AAAA9AAAAPQAAAD0AAAA8wAAAPQAAADzAAAA9AAAAO8AAAD4AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD9AAAA9QAAAP8AAAD+AAAA/gAAAP4AAAD+AAAA/gAAAP4AAAD+AAAA/gAAAP4AAAD+AAAA/gAAAP4AAAD/AAAA+gAAAPYAAAD/AAAA/gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPsAAAD2AAAA/wAAAP4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD7AQEK9gAAB/8KChD+Jycm/ygoJv8nJyb/Jygm/ycoJv8nKCb/Jygm/ycnJv8nKCb/Jycm/wsLEf8AAAf/AQEK+gAAAPYJCgD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/CgsA/wAAAPsTEDX1AAAk/0pIU/2vsKf/srOp/7GyqP+xsqj/sbKo/7GyqP+xsqj/sbKo/7Kzqf+wsaf/TUxW/QAAI/4SEDX5LRHc8wUA2/1YS+L8u7b6/765+/+8t/v/vbj7/724+/+9uPv/vbj7/7y3+/+9ufv/vLb7/1tO4/wBANv8LRLd9ygA6PctCuv/GQDn/wAA4v8AAOL/AADi/wAA4v8AAOL/AADi/wAA4v8AAOL/AADi/wAA4v8XAOf/LQvq/ykA6fspAeb2KADn/ywK5v45Juf/Oifm/zkn5/85J+f/OSfn/zkn5/85J+f/OSfn/zon5v85J+f/LAvm/igA5v8pAeb6KQDm9ikA6P8pAOb+KADm/ygA5v8oAOb/KADm/ygA5v8oAOb/KADm/ygA5v8oAOb/KADm/ykA5v8pAOf/KQDm+ykA5vYpAOf/KQDm/ikA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDn/ykA5vspAOb2KQDn/ykA5v4pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5/8pAOf6KQDn9ikA6P8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOf/KQDm+ykA5/QpAOb/KQDm/SkA5v0pAOb9KQDm/SkA5v0pAOb9KQDm/SkA5v0pAOb9KQDm/SkA5v0pAOb9KQDm/ikA5fkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAABAAAAAgAAAAAQAgAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAOsAAAD0AAAA9AAAAPQAAAD0AAAA9AAAAPQAAAD0AAAA9AAAAPQAAAD0AAAA9AAAAPQAAAD0AAAA9AAAAO8AAAD3AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD7AAAA9wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA+wAAAPcAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPsAAAD3AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD7AAAA9wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA+wAAAPcAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPsAAAD3AAAA/xYWFv94eHj/eHh4/3h4eP94eHj/eHh4/3h4eP94eHj/eHh4/3h4eP94eHj/GBgY/wAAAP8AAAD7KADj8igA4vs8GOX7lILx/ZSC8f2UgvH9lILx/ZSC8f2UgvH9lILx/ZSC8f2UgvH9lILx/T4a5fsoAOL7KADj9ikA5vcpAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5vspAOb3KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb7KQDm9ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm+ykA5vcpAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5vspAOb3KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb7KQDm9ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm/ykA5v8pAOb/KQDm+ykA5vUpAOb+KQDm/ikA5v4pAOb+KQDm/ikA5v4pAOb+KQDm/ikA5v4pAOb+KQDm/ikA5v4pAOb+KQDm/ikA5vkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
  <style>
      :root { --light: #ddd; --dark: #111 }
      html { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 18px; background-color: var(--light); color: var(--dark) }
      body { width: min(90%, 1024px); margin-inline: auto; padding-bottom: 2rem; container-type: inline-size }
      pre, textarea { font-family: ui-monospace, monospace; padding: .5rem }
      pre { width: 100cqw; overflow: clip; text-wrap: auto }
      h1 { font-size: 2.4rem }
      h2 { font-size: 2.1rem }
      h3 { font-size: 1.8rem }
      h4 { font-size: 1.5rem }
      h5 { font-size: 1.3rem }
      a { color: dodgerblue }
      table { border-collapse: collapse }
      th, td { padding: .25rem .5rem }
      tr { border-bottom: 1px solid currentColor }
      tr:first-of-type { border-top: 1px solid currentColor }
      tr:has(td):hover { background-color: rgb(from currentColor r g b / .1) }
      form { display: grid; grid-template-columns: auto 1fr; gap: .5rem; align-items: center }
      input, button { font-size: 1rem; padding: .25rem .5rem; border-radius: .25rem }
      button { cursor: pointer }
      @media (prefers-color-scheme: dark) {
          html { background-color: var(--dark); color: var(--light) }
      }
  </style>
</head>
<body>
<h1>KB API example</h1>
<nav>
  <a href="/">Application</a>
</nav>
<?php run(); ?>
</body>
</html>
