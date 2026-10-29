<?php

declare(strict_types=1);

namespace Laravel\Mcp\Exceptions;

use RuntimeException;

class InvalidClientIdMetadataDocumentException extends RuntimeException
{
    public static function because(string $clientId, string $reason): self
    {
        return new self("The client ID metadata document [{$clientId}] was rejected: {$reason}");
    }
}
