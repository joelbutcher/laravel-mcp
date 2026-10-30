<?php

declare(strict_types=1);

namespace Laravel\Mcp\Server\OAuth;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Mcp\Server\Registrar;
use Laravel\Passport\Passport;

class PassportClients
{
    /**
     * The RFC 4122 URL namespace used to derive client IDs from metadata document URLs.
     */
    protected const URL_NAMESPACE = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';

    /**
     * Create or refresh the public Passport client that represents a client ID metadata document.
     *
     * Returns null when the client has been revoked.
     */
    public function upsertFromMetadataDocument(ClientIdMetadataDocument $document): ?Model
    {
        $model = Passport::client();

        $id = $this->clientIdForMetadataDocument($document->clientId);
        $columns = $this->columns($model);

        $attributes = [
            'name' => $document->clientName,
            'redirect_uris' => $document->redirectUris,
            'grant_types' => ['authorization_code', 'refresh_token'],
            ...(in_array('client_uri', $columns, true) ? ['client_uri' => $document->clientUri] : []),
        ];

        $client = $model->newQuery()->find($id);

        if ($client instanceof Model && $client->getAttribute('revoked')) {
            return null;
        }

        if ($client instanceof Model) {
            $client->forceFill($attributes);

            if (! $client->isDirty()) {
                return $client;
            }

            $client->save();
        } else {
            $client = $model->newInstance()->forceFill([
                $model->getKeyName() => $id,
                ...$attributes,
                ...array_intersect_key(['secret' => null, 'provider' => null, 'revoked' => false], array_flip($columns)),
            ]);

            try {
                $client->save();
            } catch (UniqueConstraintViolationException) {
                return $model->newQuery()->find($id);
            }
        }

        $this->grantMcpScope($client);

        return $client;
    }

    /**
     * Derive the deterministic (version 5) UUID used as the Passport client ID for a metadata document URL.
     */
    public function clientIdForMetadataDocument(string $url): string
    {
        $hash = sha1(hex2bin(str_replace('-', '', self::URL_NAMESPACE)).$url, true);

        $bytes = substr($hash, 0, 16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x50);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    /**
     * Determine if a client ID was derived from a metadata document URL.
     *
     * Passport generates version 4 or 7 UUIDs, so version 5 UUIDs only come from metadata documents.
     */
    public function isMetadataDocumentClientId(string $id): bool
    {
        return Str::isUuid($id) && $id[14] === '5';
    }

    /**
     * Add the MCP scope to a scope-restricted Passport client.
     */
    public function grantMcpScope(mixed $client): void
    {
        if (! $client instanceof Model) {
            return;
        }

        $scopes = $client->refresh()->getAttribute('scopes');

        if (! is_array($scopes) || in_array(Registrar::OAUTH_SCOPE, $scopes, true)) {
            return;
        }

        $client->forceFill(['scopes' => [...$scopes, Registrar::OAUTH_SCOPE]])->save();
    }

    /**
     * Persist the client metadata the Passport client table has columns for.
     *
     * @param  array<string, mixed>  $metadata
     * @return array<string, mixed>
     */
    public function persistMetadata(mixed $client, array $metadata): array
    {
        if (! $client instanceof Model) {
            return [];
        }

        $supported = array_intersect(['logo_uri', 'client_uri'], $this->columns($client));
        $values = array_filter(Arr::only($metadata, $supported));

        if ($values !== []) {
            $client->forceFill($values)->save();
        }

        return array_filter($client->only($supported));
    }

    /**
     * @return array<int, string>
     */
    protected function columns(Model $client): array
    {
        return $client->getConnection()->getSchemaBuilder()->getColumnListing($client->getTable());
    }
}
