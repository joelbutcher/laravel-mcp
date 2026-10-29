<?php

declare(strict_types=1);

namespace Laravel\Mcp\Server\OAuth;

class ClientIdMetadataDocument
{
    /**
     * @param  array<int, string>  $redirectUris
     */
    public function __construct(
        public readonly string $clientId,
        public readonly string $clientName,
        public readonly array $redirectUris,
        public readonly string $tokenEndpointAuthMethod = 'none',
        public readonly ?string $clientUri = null,
        public readonly ?string $logoUri = null,
    ) {
        //
    }

    /**
     * Get the host of the client ID, which is what users should be shown on consent screens.
     */
    public function host(): string
    {
        return (string) parse_url($this->clientId, PHP_URL_HOST);
    }
}
