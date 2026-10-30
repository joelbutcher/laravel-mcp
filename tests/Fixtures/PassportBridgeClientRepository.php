<?php

declare(strict_types=1);

namespace Laravel\Passport\Bridge;

use League\OAuth2\Server\Entities\ClientEntityInterface;

class ClientRepository
{
    /**
     * @param  array<string, array{secret: ?string}>  $stored
     */
    public function __construct(public array $stored = []) {}

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        return isset($this->stored[$clientIdentifier])
            ? new Client($clientIdentifier, 'Stored Client', ['https://stored.example/callback'], $this->stored[$clientIdentifier]['secret'] !== null, null, ['authorization_code'])
            : null;
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        return isset($this->stored[$clientIdentifier]) && $this->stored[$clientIdentifier]['secret'] === $clientSecret;
    }

    public function getPersonalAccessClientEntity(string $provider): ?ClientEntityInterface
    {
        return new Client('personal-access', 'Personal Access', [], true, $provider, ['personal_access']);
    }
}
