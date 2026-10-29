<?php

declare(strict_types=1);

namespace Laravel\Passport\Bridge;

use League\OAuth2\Server\Entities\ClientEntityInterface;

class Client implements ClientEntityInterface
{
    public function __construct(
        protected string $identifier,
        protected ?string $name = null,
        protected array $redirectUri = [],
        protected bool $isConfidential = false,
        public ?string $provider = null,
        public array $grantTypes = [],
    ) {}

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getName(): string
    {
        return (string) $this->name;
    }

    public function getRedirectUri(): string|array
    {
        return $this->redirectUri;
    }

    public function isConfidential(): bool
    {
        return $this->isConfidential;
    }

    public function supportsGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }
}
