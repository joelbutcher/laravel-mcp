<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

function renderAuthorize(Request $request, array $client = []): string
{
    Route::delete('/oauth/authorize', fn (): null => null)->name('passport.authorizations.deny');
    Route::post('/oauth/authorize', fn (): null => null)->name('passport.authorizations.approve');

    app()->instance('request', $request);

    return view('mcp::authorize', [
        'client' => (object) ['id' => 'client-1', 'name' => 'Example', ...$client],
        'user' => (object) ['email' => 'user@example.com'],
        'scopes' => [],
        'authToken' => 'token',
        'request' => $request,
    ])->render();
}

it('shows the requested redirect uri', function (): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize', 'GET', ['redirect_uri' => 'https://app.example.com/callback']));

    expect($html)->toContain('You will be redirected to')
        ->and($html)->toContain('app.example.com')
        ->and($html)->toContain('https://app.example.com/callback');
});

it('falls back to the registered redirect uri', function (): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize'), ['redirect_uris' => ['https://registered.example.com/cb']]);

    expect($html)->toContain('registered.example.com');
});

it('escapes the redirect uri', function (): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize', 'GET', ['redirect_uri' => 'https://x.test/<script>alert(1)</script>']));

    expect($html)->not->toContain('<script>alert(1)</script>');
});

it('shows the host of a url client id', function (): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize', 'GET', [
        'client_id' => 'https://client.example.com/oauth/client.json',
        'redirect_uri' => 'https://app.example.com/callback',
    ]));

    expect($html)->toContain('Published by <strong class="font-semibold">client.example.com</strong>');
});

it('does not show a client id host for other clients', function (string $clientId): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize', 'GET', ['client_id' => $clientId]));

    expect($html)->not->toContain('Published by');
})->with([
    'uuid' => '0199f0a4-3b8a-7c2e-9d5f-1a2b3c4d5e6f',
    'http url' => 'http://client.example.com/oauth/client.json',
]);

it('shows the redirect host prominently', function (): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize', 'GET', ['redirect_uri' => 'https://app.example.com/callback']));

    expect($html)->toContain('You will be redirected to <strong class="font-semibold text-foreground">app.example.com</strong>');
});

it('warns when every registered redirect uri is localhost', function (array $redirectUris): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize'), ['redirect_uris' => $redirectUris]);

    expect($html)->toContain('can only send you back to this computer (localhost)');
})->with([
    'claude code' => [['http://localhost/callback', 'http://127.0.0.1/callback']],
    'ipv6 loopback' => [['http://[::1]:8080/callback']],
]);

it('does not warn when a registered redirect uri is not localhost', function (array $redirectUris): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize'), ['redirect_uris' => $redirectUris]);

    expect($html)->not->toContain('can only send you back to this computer');
})->with([
    'https' => [['https://client.example.com/callback']],
    'mixed' => [['http://localhost/callback', 'https://client.example.com/callback']],
    'https localhost' => [['https://localhost/callback']],
    'none' => [[]],
]);

it('escapes the client id host', function (): void {
    $this->withoutVite();

    $html = renderAuthorize(Request::create('/oauth/authorize', 'GET', ['client_id' => 'https://<b>x</b>.example/client.json']));

    expect($html)->not->toContain('<b>x</b>');
});
