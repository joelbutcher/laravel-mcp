<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Laravel\Mcp\Server\OAuth\ClientIdMetadataClientRepository;
use Laravel\Mcp\Server\OAuth\ClientIdMetadataDocumentResolver;
use Laravel\Mcp\Server\OAuth\PassportClients;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\ClientRepository as BridgeClientRepository;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;

const CIMD_CLIENT_URL = 'https://client.example.com/oauth/client.json';
const CIMD_CLIENT_UUID = '2136ffcd-0dfa-5408-be52-0c65a20d7be0';

function ensurePassportBridgeFixtures(): void
{
    if (! interface_exists(ClientEntityInterface::class)) {
        require_once __DIR__.'/../../../Fixtures/LeagueClientEntityInterface.php';
    }

    if (! class_exists(BridgeClient::class)) {
        require_once __DIR__.'/../../../Fixtures/PassportBridgeClient.php';
    }

    if (! class_exists(BridgeClientRepository::class)) {
        require_once __DIR__.'/../../../Fixtures/PassportBridgeClientRepository.php';
    }

    if (! class_exists(Client::class)) {
        require_once __DIR__.'/../../../Fixtures/PassportClient.php';
    }

    if (! class_exists(Passport::class)) {
        require_once __DIR__.'/../../../Fixtures/PassportPassport.php';
    }
}

function createPassportClientsTable(array $extraColumns = []): void
{
    $schema = Passport::client()->getConnection()->getSchemaBuilder();

    $schema->dropIfExists('oauth_clients');
    $schema->create('oauth_clients', function (Blueprint $table) use ($extraColumns): void {
        $table->string('id')->primary();
        $table->string('name');
        $table->string('secret')->nullable();
        $table->string('provider')->nullable();
        $table->json('redirect_uris');
        $table->json('grant_types');
        $table->boolean('revoked');

        foreach ($extraColumns as $column => $definition) {
            $definition($table, $column);
        }
    });
}

function cimdClientDocument(array $overrides = []): array
{
    return [
        'client_id' => CIMD_CLIENT_URL,
        'client_name' => 'Example Client',
        'redirect_uris' => ['https://client.example.com/callback', 'http://localhost/callback'],
        'token_endpoint_auth_method' => 'none',
        ...$overrides,
    ];
}

function cimdRepository(array $storedClients = []): ClientIdMetadataClientRepository
{
    return new ClientIdMetadataClientRepository(
        new BridgeClientRepository($storedClients),
        new ClientIdMetadataDocumentResolver,
        new PassportClients,
    );
}

function withAuthorizationRequest(string $redirectUri): void
{
    app()->instance('request', Request::create('/oauth/authorize', 'GET', ['redirect_uri' => $redirectUri]));
}

beforeEach(function (): void {
    ensurePassportBridgeFixtures();
    Passport::useClientModel(Client::class);
    createPassportClientsTable();

    config()->set('mcp.client_id_metadata_documents.enabled', true);
});

afterEach(function (): void {
    Client::flushEventListeners();
});

it('decorates the passport client repository', function (): void {
    expect(app(BridgeClientRepository::class))->toBeInstanceOf(ClientIdMetadataClientRepository::class);
});

it('maps a metadata document to a public passport client', function (): void {
    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument())]);

    $client = cimdRepository()->getClientEntity(CIMD_CLIENT_URL);

    expect($client)->toBeInstanceOf(BridgeClient::class)
        ->and($client->getIdentifier())->toBe(CIMD_CLIENT_UUID)
        ->and($client->getName())->toBe('Example Client')
        ->and($client->getRedirectUri())->toBe(['https://client.example.com/callback', 'http://localhost/callback'])
        ->and($client->isConfidential())->toBeFalse()
        ->and($client->supportsGrantType('authorization_code'))->toBeTrue()
        ->and($client->supportsGrantType('refresh_token'))->toBeTrue()
        ->and($client->supportsGrantType('client_credentials'))->toBeFalse();

    $model = Client::query()->findOrFail(CIMD_CLIENT_UUID);

    expect($model->name)->toBe('Example Client')
        ->and($model->redirect_uris)->toBe(['https://client.example.com/callback', 'http://localhost/callback'])
        ->and($model->grant_types)->toBe(['authorization_code', 'refresh_token'])
        ->and($model->secret)->toBeNull()
        ->and((bool) $model->revoked)->toBeFalse();
});

it('derives the same client id for every resolution', function (): void {
    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument())]);

    $repository = cimdRepository();

    expect($repository->getClientEntity(CIMD_CLIENT_URL)?->getIdentifier())
        ->toBe($repository->getClientEntity(CIMD_CLIENT_URL)?->getIdentifier())
        ->and(Client::query()->count())->toBe(1);
});

it('derives version 5 uuids from the url namespace', function (): void {
    $clients = new PassportClients;

    expect($clients->clientIdForMetadataDocument('https://claude.ai/oauth/claude-code-client-metadata'))->toBe('1ada8598-ee99-5f09-8c44-cf280b22e4eb')
        ->and($clients->isMetadataDocumentClientId(CIMD_CLIENT_UUID))->toBeTrue()
        ->and($clients->isMetadataDocumentClientId('0199f0a4-3b8a-7c2e-9d5f-1a2b3c4d5e6f'))->toBeFalse()
        ->and($clients->isMetadataDocumentClientId('9f1c1e0a-8d37-4f4a-9a7c-5f2f0b3f2b10'))->toBeFalse()
        ->and($clients->isMetadataDocumentClientId('not-a-uuid'))->toBeFalse();
});

it('refreshes the client when the document changes', function (): void {
    Http::fake([CIMD_CLIENT_URL => Http::sequence()
        ->push(cimdClientDocument())
        ->push(cimdClientDocument(['client_name' => 'Renamed Client', 'redirect_uris' => ['https://client.example.com/new-callback']]))]);

    cimdRepository()->getClientEntity(CIMD_CLIENT_URL);

    $this->travel(301)->seconds();

    $client = cimdRepository()->getClientEntity(CIMD_CLIENT_URL);

    expect($client->getName())->toBe('Renamed Client')
        ->and($client->getRedirectUri())->toBe(['https://client.example.com/new-callback'])
        ->and(Client::query()->findOrFail(CIMD_CLIENT_UUID)->redirect_uris)->toBe(['https://client.example.com/new-callback']);
});

it('rejects clients that have been revoked', function (): void {
    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument())]);

    cimdRepository()->getClientEntity(CIMD_CLIENT_URL);

    Client::query()->whereKey(CIMD_CLIENT_UUID)->update(['revoked' => true]);

    expect(cimdRepository()->getClientEntity(CIMD_CLIENT_URL))->toBeNull()
        ->and((bool) Client::query()->findOrFail(CIMD_CLIENT_UUID)->revoked)->toBeTrue();
});

it('rejects invalid documents and logs why', function (): void {
    $messages = [];
    Event::listen(MessageLogged::class, function (MessageLogged $event) use (&$messages): void {
        $messages[] = [$event->level, $event->message];
    });

    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument(['client_id' => 'https://attacker.example/client.json']))]);

    expect(cimdRepository()->getClientEntity(CIMD_CLIENT_URL))->toBeNull()
        ->and(Client::query()->count())->toBe(0)
        ->and($messages)->toBe([['debug', 'The client ID metadata document ['.CIMD_CLIENT_URL.'] was rejected: the document client_id does not match the URL it was fetched from.']]);
});

it('rejects the derived uuid so the document cannot be bypassed', function (): void {
    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument())]);

    $repository = cimdRepository([CIMD_CLIENT_UUID => ['secret' => null]]);
    $repository->getClientEntity(CIMD_CLIENT_URL);

    expect($repository->getClientEntity(CIMD_CLIENT_UUID))->toBeNull()
        ->and($repository->validateClient(CIMD_CLIENT_UUID, null, 'authorization_code'))->toBeFalse();
});

it('delegates url client ids to passport when disabled', function (): void {
    config()->set('mcp.client_id_metadata_documents.enabled', false);

    Http::fake();

    expect(cimdRepository()->getClientEntity(CIMD_CLIENT_URL))->toBeNull();

    Http::assertNothingSent();
});

it('delegates other clients to passport', function (): void {
    Http::fake();

    $repository = cimdRepository(['0199f0a4-3b8a-7c2e-9d5f-1a2b3c4d5e6f' => ['secret' => 'secret']]);

    expect($repository->getClientEntity('0199f0a4-3b8a-7c2e-9d5f-1a2b3c4d5e6f')?->getName())->toBe('Stored Client')
        ->and($repository->getClientEntity('missing'))->toBeNull()
        ->and($repository->validateClient('0199f0a4-3b8a-7c2e-9d5f-1a2b3c4d5e6f', 'secret', 'client_credentials'))->toBeTrue()
        ->and($repository->validateClient('0199f0a4-3b8a-7c2e-9d5f-1a2b3c4d5e6f', 'wrong', 'client_credentials'))->toBeFalse()
        ->and($repository->getPersonalAccessClientEntity('users')?->getIdentifier())->toBe('personal-access');

    Http::assertNothingSent();
});

it('never validates a secret for url client ids', function (): void {
    expect(cimdRepository([CIMD_CLIENT_URL => ['secret' => 'secret']])->validateClient(CIMD_CLIENT_URL, 'secret', 'authorization_code'))->toBeFalse();
});

it('allows the requested localhost port for portless localhost redirect uris', function (): void {
    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument())]);

    withAuthorizationRequest('http://localhost:54321/callback');

    expect(cimdRepository()->getClientEntity(CIMD_CLIENT_URL)?->getRedirectUri())->toBe([
        'https://client.example.com/callback',
        'http://localhost/callback',
        'http://localhost:54321/callback',
    ])->and(Client::query()->findOrFail(CIMD_CLIENT_UUID)->redirect_uris)->toBe([
        'https://client.example.com/callback',
        'http://localhost/callback',
    ]);
});

it('does not allow other requested redirect uris', function (string $redirectUri): void {
    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument())]);

    withAuthorizationRequest($redirectUri);

    expect(cimdRepository()->getClientEntity(CIMD_CLIENT_URL)?->getRedirectUri())->toBe([
        'https://client.example.com/callback',
        'http://localhost/callback',
    ]);
})->with([
    'different path' => 'http://localhost:54321/other',
    'https localhost' => 'https://localhost:54321/callback',
    'no port' => 'http://localhost/callback',
    'localhost subdomain' => 'http://localhost.attacker.example:54321/callback',
    'userinfo' => 'http://localhost:54321@attacker.example/callback',
    'https redirect with a port' => 'https://client.example.com:8443/callback',
    'path suffix' => 'http://localhost:54321/callback/extra',
]);

it('grants the mcp scope to scope-restricted passport clients', function (): void {
    createPassportClientsTable(['scopes' => fn (Blueprint $table, string $column) => $table->json($column)->default('[]')]);

    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument())]);

    cimdRepository()->getClientEntity(CIMD_CLIENT_URL);

    expect(Client::query()->findOrFail(CIMD_CLIENT_UUID)->scopes)->toBe(['mcp:use']);
});

it('stores the client uri but never the logo uri', function (): void {
    createPassportClientsTable([
        'client_uri' => fn (Blueprint $table, string $column) => $table->text($column)->nullable(),
        'logo_uri' => fn (Blueprint $table, string $column) => $table->text($column)->nullable(),
    ]);

    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument([
        'client_uri' => 'https://client.example.com',
        'logo_uri' => 'https://tracker.example/logo.png',
    ]))]);

    cimdRepository()->getClientEntity(CIMD_CLIENT_URL);

    $model = Client::query()->findOrFail(CIMD_CLIENT_UUID);

    expect($model->client_uri)->toBe('https://client.example.com')
        ->and($model->logo_uri)->toBeNull();
});

it('uses the existing client when another request creates it first', function (): void {
    Http::fake([CIMD_CLIENT_URL => Http::response(cimdClientDocument())]);

    Client::creating(function (Client $client): void {
        Client::withoutEvents(fn () => Client::query()->insert([
            'id' => $client->getKey(),
            'name' => 'Concurrent Client',
            'redirect_uris' => '["https://client.example.com/callback"]',
            'grant_types' => '["authorization_code","refresh_token"]',
            'revoked' => false,
        ]));
    });

    $client = cimdRepository()->getClientEntity(CIMD_CLIENT_URL);

    expect($client?->getIdentifier())->toBe(CIMD_CLIENT_UUID)
        ->and(Client::query()->count())->toBe(1);
});
