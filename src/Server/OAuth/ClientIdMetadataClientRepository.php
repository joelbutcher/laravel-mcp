<?php

declare(strict_types=1);

namespace Laravel\Mcp\Server\OAuth;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Laravel\Mcp\Exceptions\InvalidClientIdMetadataDocumentException;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\ClientRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;

/**
 * Resolves URL client IDs through their Client ID Metadata Document, delegating every other client to Passport.
 */
class ClientIdMetadataClientRepository extends ClientRepository
{
    public function __construct(
        protected ClientRepository $repository,
        protected ClientIdMetadataDocumentResolver $resolver,
        protected PassportClients $passportClients,
    ) {
        //
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        if ($this->passportClients->isMetadataDocumentClientId($clientIdentifier)) {
            return null;
        }

        if (! $this->resolver->enabled() || ! $this->resolver->handles($clientIdentifier)) {
            return $this->repository->getClientEntity($clientIdentifier);
        }

        try {
            $document = $this->resolver->resolve($clientIdentifier);
        } catch (InvalidClientIdMetadataDocumentException $invalidClientIdMetadataDocumentException) {
            Log::debug($invalidClientIdMetadataDocumentException->getMessage());

            return null;
        }

        $client = $this->passportClients->upsertFromMetadataDocument($document);

        if (! $client instanceof Model) {
            return null;
        }

        /** @var non-empty-string $identifier */
        $identifier = (string) $client->getKey();

        return new Client(
            $identifier,
            $document->clientName,
            $this->withRequestedLocalhostPort($document->redirectUris),
            false,
            null,
            ['authorization_code', 'refresh_token'],
        );
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        if ($this->passportClients->isMetadataDocumentClientId($clientIdentifier) || ($this->resolver->enabled() && $this->resolver->handles($clientIdentifier))) {
            return false;
        }

        return $this->repository->validateClient($clientIdentifier, $clientSecret, $grantType);
    }

    public function getPersonalAccessClientEntity(string $provider): ?ClientEntityInterface
    {
        return $this->repository->getPersonalAccessClientEntity($provider);
    }

    /**
     * Allow the requested "http://localhost" redirect URI on any port when the document registers it without one.
     *
     * The authorization server only ignores the port for "127.0.0.1" and "[::1]" (RFC 8252), but native clients
     * such as Claude Code register "http://localhost/callback" and listen on an ephemeral port.
     *
     * @param  array<int, string>  $redirectUris
     * @return array<int, string>
     */
    protected function withRequestedLocalhostPort(array $redirectUris): array
    {
        $container = Container::getInstance();

        if (! $container->bound('request')) {
            return $redirectUris;
        }

        /** @var Request $request */
        $request = $container->make('request');
        $requested = $request->query('redirect_uri');

        if (! is_string($requested) || in_array($requested, $redirectUris, true)) {
            return $redirectUris;
        }

        $parts = parse_url($requested);

        if (! is_array($parts) || ! isset($parts['port']) || ! str_starts_with($requested, $prefix = "http://localhost:{$parts['port']}")) {
            return $redirectUris;
        }

        $withoutPort = 'http://localhost'.substr($requested, strlen($prefix));

        return in_array($withoutPort, $redirectUris, true) ? [...$redirectUris, $requested] : $redirectUris;
    }
}
