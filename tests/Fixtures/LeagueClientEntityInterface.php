<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Entities;

interface ClientEntityInterface
{
    public function getIdentifier(): string;

    public function getName(): string;

    public function getRedirectUri(): string|array;

    public function isConfidential(): bool;

    public function supportsGrantType(string $grantType): bool;
}
