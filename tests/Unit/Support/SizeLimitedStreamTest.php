<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Utils;
use Laravel\Mcp\Support\SizeLimitedStream;

it('writes until the limit is reached', function (): void {
    $stream = new SizeLimitedStream(Utils::streamFor(''), 10);

    expect($stream->write('12345'))->toBe(5)
        ->and($stream->write('67890'))->toBe(5)
        ->and($stream->exceeded())->toBeFalse()
        ->and((string) $stream)->toBe('1234567890');
});

it('refuses writes beyond the limit', function (): void {
    $stream = new SizeLimitedStream(Utils::streamFor(''), 10);

    $stream->write('123456');

    expect($stream->write('78901'))->toBe(0)
        ->and($stream->exceeded())->toBeTrue()
        ->and((string) $stream)->toBe('123456');
});

it('refuses every write after the limit was exceeded', function (): void {
    $stream = new SizeLimitedStream(Utils::streamFor(''), 10);

    $stream->write('12345678901');

    expect($stream->write('1'))->toBe(0)
        ->and((string) $stream)->toBe('');
});
