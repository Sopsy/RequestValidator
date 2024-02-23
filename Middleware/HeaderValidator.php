<?php
declare(strict_types=1);

namespace RequestValidator\Middleware;

use HttpMessage\Contract\Request;
use HttpMessage\Contract\RequestHandler;
use HttpMessage\Contract\Response as ResponseInterface;
use HttpMessage\Message\EmptyResponse;
use HttpMessage\Message\Response;

use function preg_match;
use function str_starts_with;
use function strlen;

final class HeaderValidator implements RequestHandler
{
    public function __construct(private readonly RequestHandler $next) {
    }

    public function handle(Request $request): ResponseInterface
    {
        if ($request->attribute('isAllowedBot', 'false') === 'true') {
            return $this->next->handle($request);
        }

        $userAgent = $request->serverParam('HTTP_USER_AGENT');
        $acceptHeader = $request->serverParam('HTTP_ACCEPT');
        $queryString = $request->serverParam('QUERY_STRING');

        if (
            $userAgent === '' ||
            $userAgent === '-' ||
            strlen($userAgent) <= 10 ||
            preg_match('/[^\x20-\x7E]/', $userAgent)
        ) {
            $request->logger()->notice("Bad User-Agent header rejected: '{$userAgent}'");

            return $this->badHeadersError();
        }

        if (preg_match('/[^a-z0-9;=.,\/* \-+]/', $acceptHeader)) {
            $request->logger()->notice("Bad Accept header rejected: '{$acceptHeader}', User-Agent: '{$userAgent}'");

            return $this->badHeadersError();
        }

        if (
            $queryString !== '' &&
            !str_starts_with($request->uri()->path(), '/order/')
        ) {
            return new EmptyResponse(301, ['Location' => [$request->uri()->path()]]);
        }

        return $this->next->handle($request);
    }

    private function badHeadersError(): ResponseInterface
    {
        return new Response('Bad request headers', 400);
    }
}