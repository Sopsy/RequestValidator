<?php
declare(strict_types=1);

namespace RequestValidator\Middleware;

use Config\RequestValidatorConfig;
use HttpMessage\Contract\Request;
use HttpMessage\Contract\RequestHandler;
use HttpMessage\Contract\Response as ResponseInterface;
use HttpMessage\Message\Response;
use RuntimeException;
use stdClass;

use function _;
use function file_get_contents;
use function http_build_query;
use function in_array;
use function json_decode;
use function stream_context_create;

use const JSON_THROW_ON_ERROR;
use const PHP_INT_MAX;

final class UserChallenge implements RequestHandler
{
    public function __construct(private readonly RequestHandler $next) {
    }

    public function handle(Request $request): ResponseInterface
    {
        if ($request->attribute('isAllowedBot', 'false') === 'true') {
            return $this->next->handle($request);
        }

        // Check challenge response
        if (
            $request->method() === 'POST'
            && $request->uri()->path() === '/api/captcha-verify'
        ) {
            $hCaptchaResponse = $request->bodyParam('h-captcha-response');

            if ($hCaptchaResponse !== '' && !$this->verifyHCaptchaResponse($hCaptchaResponse)) {
                return new Response('Invalid CAPTCHA response', 403);
            }

            if ($hCaptchaResponse === '') {
                return new Response('Missing CAPTCHA response', 401);
            }

            $request = $request->withAttribute('user-challenge-pass', 'true');

            return $this->next->handle($request);
        }

        $ipBlacklisted = false; // Check if IP is blacklisted
        if (!$ipBlacklisted) {
            $showChallenge = false;
            $challengeReason = '';
            if ($request->hasUser()) {
                $challengePassAge = 0; // Check if user has a challenge pass
            } else {
                $challengePassAge = PHP_INT_MAX;
            }

            if ($challengePassAge > 14 * 3600) {
                // Get these from somewhere
                $isProxy = false;
                $isKnownBot = false;
                if ($isProxy || $isKnownBot) {
                    $showChallenge = true;
                    $challengeReason = 'Known bot IP';
                } else {
                    // Get request counts from some leaky bucket
                    $hourlyReqCount = 0;
                    $dailyReqCount = 0;

                    if ($hourlyReqCount > 150 || ($challengePassAge > 86400 && $dailyReqCount > 1200)) {
                        $showChallenge = true;
                        $challengeReason = 'High traffic from your IP';
                    }
                }
            }

            if ($showChallenge) {
                if (in_array($request->method(), ['HEAD', 'GET'])) {
                    // Add a CAPTCHA page
                    return new Response($challengeReason, 401);
                }

                return new Response('Expired session', 401);
            }
        }

        if ($request->method() === 'GET') {
            // Update request log here
        }

        return $this->next->handle($request);
    }

    private function verifyHCaptchaResponse(string $response): bool
    {
        $rvc = new RequestValidatorConfig();

        if (!isset($_SERVER['REMOTE_ADDR'])) {
            throw new RuntimeException('_SERVER REMOTE_ADDR is missing');
        }

        $url = 'https://hcaptcha.com/siteverify';
        $data = [
            'secret' => $rvc->hCaptchaSecretKey(),
            'response' => $response,
            'remoteip' => $_SERVER['REMOTE_ADDR'],
            'sitekey' => $rvc->hCaptchaSiteKey(),
        ];

        $context = stream_context_create([
            'http' => [
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => http_build_query($data),
            ],
        ]);

        $result = file_get_contents($url, false, $context);
        if (!$result) {
            return false;
        }

        try {
            /** @var stdClass $resultParsed */
            $resultParsed = json_decode($result, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Couldn\'t verify the CAPTCHA', 1, $e);
        }

        return isset($resultParsed->success) && ($resultParsed->success === true || $resultParsed->success === 'true');
    }
}