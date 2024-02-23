<?php
declare(strict_types=1);

namespace RequestValidator\Middleware;

use HttpMessage\Contract\Request;
use HttpMessage\Contract\RequestHandler;
use HttpMessage\Contract\Response as ResponseInterface;
use HttpMessage\Message\Response;

final class OldProtocolBlocker implements RequestHandler
{
    public function __construct(private readonly RequestHandler $next)
    {
        $this->next = new UserChallenge($db, $next);
    }

    public function handle(Request $request): ResponseInterface
    {
        if ($request->attribute('isAllowedBot', 'false') === 'true') {
            return $this->next->handle($request);
        }

        $scheme = $request->serverParam('REQUEST_SCHEME');
        $sslVer = $request->serverParam('SSL_PROTOCOL', '??');
        $protocolVer = $request->serverParam('SERVER_PROTOCOL', '??');

        if ($scheme === 'https' && $protocolVer !== 'HTTP/2.0') {
            $request->logger()->info("Wrong protocol rejected: '{$protocolVer}'");

            return new Response('Bad HTTP protocol version', 505);
        }

        if ($scheme === 'https' && $sslVer === 'TLSv1.2') {
            $request->logger()->info("Old TLS version rejected: '{$sslVer}'");

            return new Response('Bad TLS version', 505);
        }

        return $this->next->handle($request);
    }
}