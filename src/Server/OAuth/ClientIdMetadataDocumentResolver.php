<?php

declare(strict_types=1);

namespace Laravel\Mcp\Server\OAuth;

use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Utils;
use GuzzleHttp\RequestOptions;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache as CacheFactory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Laravel\Mcp\Exceptions\InvalidClientIdMetadataDocumentException;
use Laravel\Mcp\Support\AddressGuard;
use Laravel\Mcp\Support\SizeLimitedStream;

class ClientIdMetadataDocumentResolver
{
    /**
     * Token endpoint authentication methods that rely on a shared secret, which a public document cannot hold.
     *
     * @var array<int, string>
     */
    protected const SHARED_SECRET_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'client_secret_jwt'];

    /**
     * Determine if Client ID Metadata Documents are enabled.
     */
    public function enabled(): bool
    {
        return (bool) config('mcp.client_id_metadata_documents.enabled', false);
    }

    /**
     * Determine if the client identifier should be resolved as a metadata document URL.
     */
    public function handles(string $clientId): bool
    {
        return str_starts_with($clientId, 'https://');
    }

    /**
     * Fetch, validate, and cache the metadata document identified by the given URL.
     *
     * @throws InvalidClientIdMetadataDocumentException
     */
    public function resolve(string $clientId): ClientIdMetadataDocument
    {
        $host = $this->validateClientId($clientId);

        if (! $this->isAllowedHost($host)) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, "the host [{$host}] is not an allowed client ID metadata document host.");
        }

        $key = 'mcp:client-id-metadata-document:'.hash('sha256', $clientId);

        /** @var array<string, mixed>|null $cached */
        $cached = $this->cache()->get($key);

        if (is_array($cached)) {
            return $this->validateDocument($clientId, $cached);
        }

        [$data, $ttl] = $this->fetch($clientId, $host);

        $document = $this->validateDocument($clientId, $data);

        if ($ttl > 0) {
            $this->cache()->put($key, $data, $ttl);
        }

        return $document;
    }

    /**
     * Validate the client identifier URL and return its host.
     *
     * @throws InvalidClientIdMetadataDocumentException
     */
    protected function validateClientId(string $clientId): string
    {
        $parts = parse_url($clientId);

        if (! is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || ! isset($parts['host']) || $parts['host'] === '') {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the client ID must be an https URL.');
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the client ID must not contain credentials.');
        }

        if (isset($parts['fragment']) || str_contains($clientId, '#')) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the client ID must not contain a fragment.');
        }

        if (isset($parts['query'])) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the client ID must not contain a query string.');
        }

        $path = $parts['path'] ?? '';

        if ($path === '' || $path === '/') {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the client ID must contain a path.');
        }

        if (array_intersect(explode('/', $path), ['.', '..']) !== []) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the client ID must not contain dot path segments.');
        }

        return strtolower($parts['host']);
    }

    protected function isAllowedHost(string $host): bool
    {
        /** @var array<int, string> $allowedHosts */
        $allowedHosts = config('mcp.client_id_metadata_documents.allowed_hosts', ['*']);

        return Str::is(array_map(strtolower(...), $allowedHosts), $host);
    }

    /**
     * Fetch the document, returning the decoded JSON and how long it may be cached for.
     *
     * @return array{0: array<string, mixed>, 1: int}
     *
     * @throws InvalidClientIdMetadataDocumentException
     */
    protected function fetch(string $clientId, string $host): array
    {
        $guard = new AddressGuard;

        if (! $guard->isPublicHost($host, allowLoopback: (bool) config('mcp.client_id_metadata_documents.allow_loopback', false))) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the host is private, internal, or cannot be resolved.');
        }

        $maxBytes = $this->maxBytes();
        $sink = new SizeLimitedStream(Utils::streamFor(Utils::tryFopen('php://temp', 'w+')), $maxBytes);

        try {
            $response = $guard->pin(Http::accept('application/json'))
                ->timeout((int) config('mcp.client_id_metadata_documents.timeout', 5))
                ->connectTimeout(2)
                ->withOptions([
                    'allow_redirects' => false,
                    'sink' => $sink,
                    ...$this->transferLimits($maxBytes),
                ])
                ->get($clientId);
        } catch (ConnectionException|TransferException|MalformedUriException) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, $sink->exceeded()
                ? "the document is larger than {$maxBytes} bytes."
                : 'the document could not be fetched.');
        }

        if ($sink->exceeded()) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, "the document is larger than {$maxBytes} bytes.");
        }

        if ($response->status() !== 200) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, "the document responded with status [{$response->status()}].");
        }

        if (! $this->isJsonContentType($response->header('Content-Type'))) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document is not served as JSON.');
        }

        $body = $response->body();

        if (strlen($body) > $maxBytes) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, "the document is larger than {$maxBytes} bytes.");
        }

        $data = json_decode($body, true);

        if (! is_array($data) || array_is_list($data)) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document is not a JSON object.');
        }

        /** @var array<string, mixed> $data */
        return [$data, $this->cacheTtl($response)];
    }

    /**
     * Restrict the transfer to HTTPS and cap its size, using the options the installed Guzzle version supports.
     *
     * Guzzle 8 rejects these cURL options in favour of its own "protocols" option; the sink caps the size either way.
     *
     * @return array<string, mixed>
     */
    protected function transferLimits(int $maxBytes): array
    {
        if (defined(RequestOptions::class.'::PROTOCOLS')) {
            return ['protocols' => ['https']];
        }

        if (! defined('CURLOPT_PROTOCOLS')) {
            return [];
        }

        return ['curl' => [
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_MAXFILESIZE => $maxBytes,
        ]];
    }

    protected function isJsonContentType(string $contentType): bool
    {
        $mediaType = strtolower(trim(Str::before($contentType, ';')));

        return $mediaType === 'application/json'
            || (str_starts_with($mediaType, 'application/') && str_ends_with($mediaType, '+json'));
    }

    /**
     * Determine how long a fetched document may be cached for, honouring its Cache-Control header within the configured bounds.
     */
    protected function cacheTtl(Response $response): int
    {
        $directives = array_map(
            fn (string $directive): string => strtolower(trim($directive)),
            explode(',', $response->header('Cache-Control')),
        );

        if (array_intersect($directives, ['no-store', 'no-cache']) !== []) {
            return 0;
        }

        $ttl = (int) config('mcp.client_id_metadata_documents.cache.ttl', 300);

        foreach ($directives as $directive) {
            if (preg_match('/^max-age\s*=\s*"?(\d+)"?$/', $directive, $matches) === 1) {
                $ttl = (int) $matches[1];
            }
        }

        return max(
            (int) config('mcp.client_id_metadata_documents.cache.min_ttl', 60),
            min($ttl, (int) config('mcp.client_id_metadata_documents.cache.max_ttl', 86_400)),
        );
    }

    /**
     * @param  array<string, mixed>  $data
     *
     * @throws InvalidClientIdMetadataDocumentException
     */
    protected function validateDocument(string $clientId, array $data): ClientIdMetadataDocument
    {
        if (! is_string($data['client_id'] ?? null) || $data['client_id'] !== $clientId) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document client_id does not match the URL it was fetched from.');
        }

        $clientName = $data['client_name'] ?? null;

        if (! is_string($clientName) || trim($clientName) === '' || mb_strlen($clientName) > 255) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document must contain a client_name.');
        }

        $authMethod = $this->validateAuthentication($clientId, $data);

        if (array_key_exists('grant_types', $data) && (! is_array($data['grant_types']) || ! in_array('authorization_code', $data['grant_types'], true))) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document must allow the authorization_code grant.');
        }

        return new ClientIdMetadataDocument(
            clientId: $clientId,
            clientName: trim($clientName),
            redirectUris: $this->validateRedirectUris($clientId, $data['redirect_uris'] ?? null),
            tokenEndpointAuthMethod: $authMethod,
            clientUri: $this->optionalUrl($data['client_uri'] ?? null),
            logoUri: $this->optionalUrl($data['logo_uri'] ?? null),
        );
    }

    /**
     * Ensure the document describes a client that can be treated as public, returning its authentication method.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws InvalidClientIdMetadataDocumentException
     */
    protected function validateAuthentication(string $clientId, array $data): string
    {
        if (array_key_exists('client_secret', $data) || array_key_exists('client_secret_expires_at', $data)) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document must not contain a client secret.');
        }

        foreach ((array) data_get($data, 'jwks.keys', []) as $key) {
            if (is_array($key) && array_intersect(['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'], array_keys($key)) !== []) {
                throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document must not contain private or symmetric keys.');
            }
        }

        $method = $data['token_endpoint_auth_method'] ?? 'none';

        if ($method === 'none') {
            return $method;
        }

        if ($method === 'private_key_jwt') {
            if (config('mcp.client_id_metadata_documents.private_key_jwt', 'reject') === 'public') {
                return $method;
            }

            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the private_key_jwt token endpoint authentication method is not supported.');
        }

        if (is_string($method) && in_array($method, self::SHARED_SECRET_AUTH_METHODS, true)) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, "the shared secret authentication method [{$method}] cannot be used by a metadata document client.");
        }

        throw InvalidClientIdMetadataDocumentException::because($clientId, 'the token endpoint authentication method is not supported.');
    }

    /**
     * @return array<int, string>
     *
     * @throws InvalidClientIdMetadataDocumentException
     */
    protected function validateRedirectUris(string $clientId, mixed $redirectUris): array
    {
        if (! is_array($redirectUris) || $redirectUris === [] || ! array_is_list($redirectUris) || count($redirectUris) > 10) {
            throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document must contain between one and ten redirect_uris.');
        }

        $policy = RedirectUriPolicy::fromConfig();

        foreach ($redirectUris as $redirectUri) {
            if (! is_string($redirectUri) || strlen($redirectUri) > 1024 || ! $policy->isValid($redirectUri)) {
                throw InvalidClientIdMetadataDocumentException::because($clientId, 'the document contains an invalid redirect URI.');
            }

            if (parse_url($redirectUri, PHP_URL_SCHEME) === 'http' && ! $policy->isLocalhost($redirectUri)) {
                throw InvalidClientIdMetadataDocumentException::because($clientId, "the redirect URI [{$redirectUri}] must use https or a loopback host.");
            }

            if (! $policy->isPermitted($redirectUri)) {
                throw InvalidClientIdMetadataDocumentException::because($clientId, "the redirect URI [{$redirectUri}] is not a permitted redirect domain.");
            }
        }

        /** @var array<int, string> $redirectUris */
        return $redirectUris;
    }

    protected function optionalUrl(mixed $value): ?string
    {
        return is_string($value) && strlen($value) <= 2048 && Str::isUrl($value, ['https']) ? $value : null;
    }

    protected function maxBytes(): int
    {
        return (int) config('mcp.client_id_metadata_documents.max_bytes', 5120);
    }

    protected function cache(): Cache
    {
        /** @var string|null $store */
        $store = config('mcp.client_id_metadata_documents.cache.store');

        return CacheFactory::store($store);
    }
}
