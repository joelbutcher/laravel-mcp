<?php

declare(strict_types=1);

namespace Laravel\Mcp\Support;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

/**
 * A response sink that stops accepting writes beyond a byte limit.
 *
 * A short write makes the cURL handler abort the transfer, so oversized bodies are never fully downloaded.
 */
class SizeLimitedStream implements StreamInterface
{
    use StreamDecoratorTrait;

    protected int $written = 0;

    protected bool $exceeded = false;

    public function __construct(protected StreamInterface $stream, protected int $limit)
    {
        //
    }

    public function write(string $string): int
    {
        if ($this->exceeded || $this->written + strlen($string) > $this->limit) {
            $this->exceeded = true;

            return 0;
        }

        $this->written += strlen($string);

        return $this->stream->write($string);
    }

    /**
     * Determine if a write was refused because it would have exceeded the limit.
     */
    public function exceeded(): bool
    {
        return $this->exceeded;
    }
}
