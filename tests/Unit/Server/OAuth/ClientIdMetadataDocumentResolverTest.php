<?php

declare(strict_types=1);

use GuzzleHttp\RequestOptions;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Laravel\Mcp\Exceptions\InvalidClientIdMetadataDocumentException;
use Laravel\Mcp\Server\OAuth\ClientIdMetadataDocument;
use Laravel\Mcp\Server\OAuth\ClientIdMetadataDocumentResolver;
use Laravel\Mcp\Support\AddressGuard;
use Laravel\Mcp\Support\SizeLimitedStream;

const CIMD_URL = 'https://client.example.com/oauth/client.json';

function cimdDocument(array $overrides = []): array
{
    return [
        'client_id' => CIMD_URL,
        'client_name' => 'Example Client',
        'redirect_uris' => ['https://client.example.com/callback', 'http://localhost/callback'],
        'grant_types' => ['authorization_code', 'refresh_token'],
        'token_endpoint_auth_method' => 'none',
        ...$overrides,
    ];
}

function fakeCimd(mixed $body = null, int $status = 200, array $headers = ['Content-Type' => 'application/json']): void
{
    Http::fake([CIMD_URL => Http::response($body ?? cimdDocument(), $status, $headers)]);
}

function resolveCimd(string $url = CIMD_URL): ClientIdMetadataDocument
{
    return (new ClientIdMetadataDocumentResolver)->resolve($url);
}

function expectCimdRejected(string $reason, string $url = CIMD_URL): void
{
    expect(fn (): ClientIdMetadataDocument => resolveCimd($url))
        ->toThrow(InvalidClientIdMetadataDocumentException::class, $reason);
}

beforeEach(function (): void {
    config()->set('mcp.client_id_metadata_documents.enabled', true);
});

it('resolves a valid document', function (): void {
    fakeCimd(cimdDocument([
        'client_uri' => 'https://client.example.com',
        'logo_uri' => 'https://client.example.com/logo.png',
    ]));

    $document = resolveCimd();

    expect($document->clientId)->toBe(CIMD_URL)
        ->and($document->clientName)->toBe('Example Client')
        ->and($document->redirectUris)->toBe(['https://client.example.com/callback', 'http://localhost/callback'])
        ->and($document->tokenEndpointAuthMethod)->toBe('none')
        ->and($document->clientUri)->toBe('https://client.example.com')
        ->and($document->logoUri)->toBe('https://client.example.com/logo.png')
        ->and($document->host())->toBe('client.example.com');
});

it('only handles https client ids', function (string $clientId, bool $expected): void {
    expect((new ClientIdMetadataDocumentResolver)->handles($clientId))->toBe($expected);
})->with([
    [CIMD_URL, true],
    ['http://client.example.com/client.json', false],
    ['9f1c1e0a-8d37-4f4a-9a7c-5f2f0b3f2b10', false],
]);

it('is disabled by default', function (): void {
    config()->set('mcp.client_id_metadata_documents', []);

    expect((new ClientIdMetadataDocumentResolver)->enabled())->toBeFalse();
});

it('rejects client ids that are not valid metadata document urls', function (string $url, string $reason): void {
    Http::fake();

    expectCimdRejected($reason, $url);

    Http::assertNothingSent();
})->with([
    'http' => ['http://client.example.com/client.json', 'must be an https URL'],
    'not a url' => ['https://', 'must be an https URL'],
    'userinfo' => ['https://user:pass@client.example.com/client.json', 'must not contain credentials'],
    'fragment' => ['https://client.example.com/client.json#frag', 'must not contain a fragment'],
    'empty fragment' => ['https://client.example.com/client.json#', 'must not contain a fragment'],
    'query' => ['https://client.example.com/client.json?v=1', 'must not contain a query string'],
    'no path' => ['https://client.example.com', 'must contain a path'],
    'root path' => ['https://client.example.com/', 'must contain a path'],
    'dot segment' => ['https://client.example.com/./client.json', 'must not contain dot path segments'],
    'dot dot segment' => ['https://client.example.com/oauth/../client.json', 'must not contain dot path segments'],
]);

it('rejects hosts that are not allowed', function (array $allowedHosts): void {
    config()->set('mcp.client_id_metadata_documents.allowed_hosts', $allowedHosts);

    Http::fake();

    expectCimdRejected('is not an allowed client ID metadata document host');

    Http::assertNothingSent();
})->with([
    'empty' => [[]],
    'other host' => [['claude.ai', 'chatgpt.com']],
    'suffix without wildcard' => [['example.com']],
    'lookalike' => [['client.example.com.evil.test']],
]);

it('accepts allowed hosts, including wildcards', function (array $allowedHosts): void {
    config()->set('mcp.client_id_metadata_documents.allowed_hosts', $allowedHosts);

    fakeCimd();

    expect(resolveCimd()->clientName)->toBe('Example Client');
})->with([
    'any' => [['*']],
    'exact' => [['client.example.com']],
    'exact with different case' => [['Client.Example.COM']],
    'subdomain wildcard' => [['*.example.com']],
]);

it('rejects documents whose client_id does not match the url', function (mixed $clientId): void {
    fakeCimd(cimdDocument(['client_id' => $clientId]));

    expectCimdRejected('client_id does not match');
})->with([
    'different path' => 'https://client.example.com/other.json',
    'explicit default port' => 'https://client.example.com:443/oauth/client.json',
    'trailing slash' => CIMD_URL.'/',
    'different host case' => 'https://CLIENT.example.com/oauth/client.json',
    'different host' => 'https://attacker.example/oauth/client.json',
    'missing' => null,
    'not a string' => [['https://client.example.com/oauth/client.json']],
]);

it('rejects documents without a client name', function (mixed $clientName): void {
    fakeCimd(cimdDocument(['client_name' => $clientName]));

    expectCimdRejected('must contain a client_name');
})->with([
    'missing' => null,
    'empty' => '   ',
    'not a string' => 123,
    'too long' => str_repeat('a', 256),
]);

it('rejects documents without valid redirect uris', function (mixed $redirectUris): void {
    fakeCimd(cimdDocument(['redirect_uris' => $redirectUris]));

    expectCimdRejected('between one and ten redirect_uris');
})->with([
    'missing' => null,
    'empty' => [[]],
    'not a list' => [['a' => 'https://client.example.com/callback']],
    'too many' => [array_map(fn (int $i): string => "https://client.example.com/{$i}", range(1, 11))],
    'string' => 'https://client.example.com/callback',
]);

it('rejects documents containing an invalid redirect uri', function (mixed $redirectUri): void {
    fakeCimd(cimdDocument(['redirect_uris' => [$redirectUri]]));

    expectCimdRejected('invalid redirect URI');
})->with([
    'not a string' => 42,
    'userinfo' => 'https://user@client.example.com/callback',
    'unconfigured custom scheme' => 'cursor://callback',
    'too long' => 'https://client.example.com/'.str_repeat('a', 1024),
]);

it('rejects plain http redirect uris that are not loopback', function (): void {
    fakeCimd(cimdDocument(['redirect_uris' => ['http://client.example.com/callback']]));

    expectCimdRejected('must use https or a loopback host');
});

it('rejects redirect uris that are not permitted redirect domains', function (): void {
    config()->set('mcp.redirect_domains', ['https://client.example.com']);

    fakeCimd(cimdDocument(['redirect_uris' => ['https://client.example.com/callback', 'https://attacker.example/callback']]));

    expectCimdRejected('[https://attacker.example/callback] is not a permitted redirect domain');
});

it('accepts configured custom scheme redirect uris', function (): void {
    config()->set('mcp.custom_schemes', ['cursor']);

    fakeCimd(cimdDocument(['redirect_uris' => ['cursor://anysphere.cursor-retrieval/oauth/callback']]));

    expect(resolveCimd()->redirectUris)->toBe(['cursor://anysphere.cursor-retrieval/oauth/callback']);
});

it('rejects documents that contain a client secret', function (string $field): void {
    fakeCimd(cimdDocument([$field => 'secret']));

    expectCimdRejected('must not contain a client secret');
})->with(['client_secret', 'client_secret_expires_at']);

it('rejects documents that contain private or symmetric keys', function (array $key): void {
    fakeCimd(cimdDocument(['jwks' => ['keys' => [$key]]]));

    expectCimdRejected('must not contain private or symmetric keys');
})->with([
    'rsa private key' => [['kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB', 'd' => 'secret']],
    'symmetric key' => [['kty' => 'oct', 'k' => 'secret']],
]);

it('accepts documents with public keys', function (): void {
    fakeCimd(cimdDocument(['jwks' => ['keys' => [['kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB']]]]));

    expect(resolveCimd()->clientName)->toBe('Example Client');
});

it('rejects shared secret token endpoint authentication methods', function (string $method): void {
    fakeCimd(cimdDocument(['token_endpoint_auth_method' => $method]));

    expectCimdRejected("shared secret authentication method [{$method}]");
})->with(['client_secret_basic', 'client_secret_post', 'client_secret_jwt']);

it('rejects unsupported token endpoint authentication methods', function (mixed $method): void {
    fakeCimd(cimdDocument(['token_endpoint_auth_method' => $method]));

    expectCimdRejected('token endpoint authentication method is not supported');
})->with(['tls_client_auth', 'self_signed_tls_client_auth', 'unknown', 1]);

it('treats a missing token endpoint authentication method as none', function (): void {
    $document = cimdDocument();
    unset($document['token_endpoint_auth_method']);

    fakeCimd($document);

    expect(resolveCimd()->tokenEndpointAuthMethod)->toBe('none');
});

it('rejects private_key_jwt documents by default', function (): void {
    fakeCimd(cimdDocument([
        'token_endpoint_auth_method' => 'private_key_jwt',
        'jwks_uri' => 'https://client.example.com/jwks.json',
    ]));

    expectCimdRejected('private_key_jwt token endpoint authentication method is not supported');
});

it('accepts private_key_jwt documents as public clients when configured', function (): void {
    config()->set('mcp.client_id_metadata_documents.private_key_jwt', 'public');

    fakeCimd(cimdDocument([
        'token_endpoint_auth_method' => 'private_key_jwt',
        'jwks_uri' => 'https://client.example.com/jwks.json',
    ]));

    expect(resolveCimd()->tokenEndpointAuthMethod)->toBe('private_key_jwt');
});

it('rejects documents that do not allow the authorization code grant', function (mixed $grantTypes): void {
    fakeCimd(cimdDocument(['grant_types' => $grantTypes]));

    expectCimdRejected('must allow the authorization_code grant');
})->with([
    'client credentials only' => [['client_credentials']],
    'not a list' => 'authorization_code',
]);

it('rejects responses other than 200', function (int $status): void {
    fakeCimd(cimdDocument(), $status);

    expectCimdRejected("responded with status [{$status}]");
})->with([201, 203, 204, 304, 400, 401, 403, 404, 410, 429, 500, 503]);

it('does not follow redirects', function (int $status): void {
    $options = [];

    Http::fake(function (Request $request, array $requestOptions) use (&$options, $status) {
        $options[] = $requestOptions;

        return $request->url() === CIMD_URL
            ? Http::response('', $status, ['Location' => 'https://client.example.com/moved.json'])
            : Http::response(cimdDocument(['client_id' => 'https://client.example.com/moved.json']));
    });

    expectCimdRejected("responded with status [{$status}]");

    expect($options)->toHaveCount(1)
        ->and($options[0]['allow_redirects'])->toBeFalse();
})->with([301, 302, 303, 307, 308]);

it('rejects documents that are not served as json', function (string $contentType): void {
    fakeCimd(json_encode(cimdDocument()), headers: ['Content-Type' => $contentType]);

    expectCimdRejected('is not served as JSON');
})->with(['text/html', 'text/plain', 'application/jsonp', 'application/x-www-form-urlencoded', '']);

it('accepts json media types with parameters and structured syntax suffixes', function (string $contentType): void {
    fakeCimd(json_encode(cimdDocument()), headers: ['Content-Type' => $contentType]);

    expect(resolveCimd()->clientName)->toBe('Example Client');
})->with(['application/json; charset=utf-8', 'Application/JSON', 'application/oauth-client+json']);

it('rejects documents that are not json objects', function (string $body): void {
    fakeCimd($body);

    expectCimdRejected('is not a JSON object');
})->with([
    'invalid json' => '{"client_id":',
    'list' => '["https://client.example.com/oauth/client.json"]',
    'string' => '"https://client.example.com/oauth/client.json"',
    'empty object' => '[]',
]);

it('rejects documents larger than the size limit', function (): void {
    fakeCimd(cimdDocument(['client_uri' => 'https://client.example.com/'.str_repeat('a', 5_200)]));

    expectCimdRejected('is larger than 5120 bytes');
});

it('applies the configured size limit', function (): void {
    config()->set('mcp.client_id_metadata_documents.max_bytes', 100);

    fakeCimd();

    expectCimdRejected('is larger than 100 bytes');
});

it('accepts documents exactly at the size limit', function (): void {
    $body = json_encode(cimdDocument());
    config()->set('mcp.client_id_metadata_documents.max_bytes', strlen($body));

    fakeCimd($body);

    expect(resolveCimd()->clientName)->toBe('Example Client');
});

it('caps the response size while the body is downloaded', function (): void {
    $options = null;

    Http::fake(function (Request $request, array $requestOptions) use (&$options) {
        $options = $requestOptions;

        return Http::response(cimdDocument());
    });

    resolveCimd();

    expect($options['sink'])->toBeInstanceOf(SizeLimitedStream::class);

    if (defined(RequestOptions::class.'::PROTOCOLS')) {
        expect($options['protocols'])->toBe(['https']);
    } else {
        expect($options['curl'][CURLOPT_MAXFILESIZE])->toBe(5_120)
            ->and($options['curl'][CURLOPT_PROTOCOLS])->toBe(CURLPROTO_HTTPS);
    }
});

it('rejects documents whose download was cut off at the size limit', function (): void {
    Http::fake(function (Request $request, array $options) {
        $options['sink']->write(str_repeat('a', 5_121));

        return Http::response(cimdDocument());
    });

    expectCimdRejected('is larger than 5120 bytes');
});

it('reports an aborted oversized download as too large', function (): void {
    Http::fake(function (Request $request, array $options): void {
        $options['sink']->write(str_repeat('a', 5_121));

        throw new ConnectionException('Unable to write to stream');
    });

    expectCimdRejected('is larger than 5120 bytes');
});

it('rejects documents that time out', function (): void {
    Http::fake([CIMD_URL => Http::failedConnection('cURL error 28: Operation timed out after 5001 milliseconds')]);

    expectCimdRejected('could not be fetched');
});

it('rejects documents that cannot be fetched', function (): void {
    Http::fake([CIMD_URL => Http::failedConnection()]);

    expectCimdRejected('could not be fetched');
});

it('applies the configured timeout', function (): void {
    config()->set('mcp.client_id_metadata_documents.timeout', 3);

    $options = null;

    Http::fake(function (Request $request, array $requestOptions) use (&$options) {
        $options = $requestOptions;

        return Http::response(cimdDocument());
    });

    resolveCimd();

    expect($options['timeout'])->toBe(3)
        ->and($options['connect_timeout'])->toBe(2);
});

it('refuses to fetch documents from special use addresses', function (string $address): void {
    AddressGuard::resolveHostsUsing(fn (string $host): array => ['93.184.216.34', $address]);

    Http::fake();

    expectCimdRejected('private, internal, or cannot be resolved');

    Http::assertNothingSent();
})->with([
    'unspecified' => '0.0.0.0',
    'loopback' => '127.0.0.1',
    'rfc1918 10/8' => '10.0.0.5',
    'rfc1918 172.16/12' => '172.16.0.1',
    'rfc1918 192.168/16' => '192.168.1.1',
    'cloud metadata' => '169.254.169.254',
    'carrier grade nat' => '100.64.0.1',
    'ipv4 multicast' => '224.0.0.1',
    'benchmarking' => '198.18.0.1',
    'ipv6 loopback' => '::1',
    'ipv6 link local' => 'fe80::1',
    'ipv6 unique local' => 'fc00::1',
    'ipv4 mapped ipv6' => '::ffff:10.0.0.1',
    'nat64' => '64:ff9b::a00:1',
    '6to4' => '2002:7f00:1::',
    'teredo' => '2001:0:4136:e378:8000:63bf:3fff:fdd2',
]);

it('refuses to fetch documents from ip literal special use addresses', function (string $url): void {
    Http::fake();

    expect(fn (): ClientIdMetadataDocument => resolveCimd($url))
        ->toThrow(InvalidClientIdMetadataDocumentException::class, 'private, internal, or cannot be resolved');

    Http::assertNothingSent();
})->with([
    'https://127.0.0.1/client.json',
    'https://169.254.169.254/latest/meta-data',
    'https://[::1]/client.json',
    'https://10.0.0.1:8443/client.json',
]);

it('refuses to fetch documents from unresolvable hosts', function (): void {
    AddressGuard::resolveHostsUsing(fn (string $host): array => []);

    Http::fake();

    expectCimdRejected('private, internal, or cannot be resolved');

    Http::assertNothingSent();
});

it('allows loopback hosts only when configured', function (): void {
    config()->set('mcp.client_id_metadata_documents.allow_loopback', true);
    AddressGuard::resolveHostsUsing(fn (string $host): array => ['127.0.0.1']);

    fakeCimd();

    expect(resolveCimd()->clientName)->toBe('Example Client');
});

it('still refuses private addresses when loopback hosts are allowed', function (): void {
    config()->set('mcp.client_id_metadata_documents.allow_loopback', true);
    AddressGuard::resolveHostsUsing(fn (string $host): array => ['10.0.0.1']);

    Http::fake();

    expectCimdRejected('private, internal, or cannot be resolved');
});

it('pins the request to the addresses that were checked', function (): void {
    AddressGuard::resolveHostsUsing(fn (string $host): array => ['93.184.216.35']);

    $pin = null;

    Http::fake(function (Request $request, array $options) use (&$pin) {
        $pin = $options['curl'][CURLOPT_RESOLVE] ?? null;

        return Http::response(cimdDocument());
    });

    resolveCimd();

    expect($pin)->toBe(['client.example.com:443:93.184.216.35']);
});

it('caches valid documents', function (): void {
    fakeCimd();

    resolveCimd();
    resolveCimd();

    Http::assertSentCount(1);
});

it('honours the cache control max age within the configured bounds', function (string $cacheControl, int $fresh, int $expired): void {
    fakeCimd(headers: ['Content-Type' => 'application/json', 'Cache-Control' => $cacheControl]);

    resolveCimd();

    $this->travel($fresh)->seconds();
    resolveCimd();
    Http::assertSentCount(1);

    $this->travel($expired - $fresh)->seconds();
    resolveCimd();
    Http::assertSentCount(2);
})->with([
    'max age' => ['public, max-age=600', 599, 601],
    'quoted max age' => ['max-age="600"', 599, 601],
    'below the minimum' => ['max-age=5', 59, 61],
    'above the maximum' => ['max-age=31536000', 86_399, 86_401],
    'no max age uses the default' => ['public', 299, 301],
]);

it('uses the default ttl when there is no cache control header', function (): void {
    fakeCimd();

    resolveCimd();

    $this->travel(299)->seconds();
    resolveCimd();
    Http::assertSentCount(1);

    $this->travel(2)->seconds();
    resolveCimd();
    Http::assertSentCount(2);
});

it('does not cache documents marked no-store or no-cache', function (string $cacheControl): void {
    fakeCimd(headers: ['Content-Type' => 'application/json', 'Cache-Control' => $cacheControl]);

    resolveCimd();
    resolveCimd();

    Http::assertSentCount(2);
})->with(['no-store', 'no-cache', 'private, no-store, max-age=600']);

it('does not cache failed fetches', function (): void {
    Http::fake([CIMD_URL => Http::sequence()
        ->push('Unavailable', 503)
        ->push(cimdDocument(), 200, ['Content-Type' => 'application/json'])]);

    expectCimdRejected('responded with status [503]');

    expect(resolveCimd()->clientName)->toBe('Example Client');

    Http::assertSentCount(2);
});

it('does not cache invalid documents', function (): void {
    Http::fake([CIMD_URL => Http::sequence()
        ->push(cimdDocument(['client_id' => 'https://attacker.example/client.json']), 200, ['Content-Type' => 'application/json'])
        ->push(cimdDocument(), 200, ['Content-Type' => 'application/json'])]);

    expectCimdRejected('client_id does not match');

    expect(resolveCimd()->clientName)->toBe('Example Client');

    Http::assertSentCount(2);
});

it('revalidates cached documents against the current configuration', function (): void {
    fakeCimd();

    resolveCimd();

    config()->set('mcp.redirect_domains', ['https://other.example']);

    expectCimdRejected('is not a permitted redirect domain');

    Http::assertSentCount(1);
});

it('checks the host allowlist before using the cache', function (): void {
    fakeCimd();

    resolveCimd();

    config()->set('mcp.client_id_metadata_documents.allowed_hosts', ['claude.ai']);

    expectCimdRejected('is not an allowed client ID metadata document host');
});

it('uses the configured cache store', function (): void {
    config()->set('cache.stores.cimd', ['driver' => 'array']);
    config()->set('mcp.client_id_metadata_documents.cache.store', 'cimd');

    fakeCimd();

    resolveCimd();

    expect(cache()->store('cimd')->get('mcp:client-id-metadata-document:'.hash('sha256', CIMD_URL)))->toBe(cimdDocument())
        ->and(cache()->store('array')->get('mcp:client-id-metadata-document:'.hash('sha256', CIMD_URL)))->toBeNull();
});

it('accepts the live claude code document shape', function (): void {
    $url = 'https://claude.ai/oauth/claude-code-client-metadata';

    Http::fake([$url => Http::response([
        'client_id' => $url,
        'client_name' => 'Claude Code',
        'client_uri' => 'https://claude.ai',
        'redirect_uris' => ['http://localhost/callback', 'http://127.0.0.1/callback'],
        'grant_types' => ['authorization_code', 'refresh_token'],
        'response_types' => ['code'],
        'token_endpoint_auth_method' => 'none',
    ])]);

    expect(resolveCimd($url)->redirectUris)->toBe(['http://localhost/callback', 'http://127.0.0.1/callback']);
});
