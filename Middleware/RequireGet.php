<?php
declare(strict_types=1);

namespace RequestValidator\Middleware;

use HttpMessage\Contract\Request;
use HttpMessage\Contract\RequestHandler;
use HttpMessage\Contract\Response as ResponseInterface;
use HttpMessage\Message\Response;

use function _;

final class RequireGet implements RequestHandler
{
    public function __construct(private readonly RequestHandler $next) {
    }

    public function handle(Request $request): ResponseInterface
    {
        if ($request->method() !== 'GET' && $request->method() !== 'HEAD') {
            return new Response('Request method is not allowed.' . "\x00" . 'GET, HEAD', 405);
        }

        return $this->next->handle($request);
    }
}