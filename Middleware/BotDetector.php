<?php /** @noinspection HttpUrlsUsage - These are in user agent strings */
declare(strict_types=1);

namespace RequestValidator\Middleware;

use Config\BaseConfig;
use Config\RequestValidatorConfig;
use HttpMessage\Contract\Request;
use HttpMessage\Contract\RequestHandler;
use HttpMessage\Contract\Response as ResponseInterface;
use HttpMessage\Message\EmptyResponse;
use HttpMessage\Message\Response;
use RequestValidator\View\BadBot;
use RequestValidator\View\FakeBot;

use function gethostbyaddr;
use function gethostbyname;
use function hash_equals;
use function implode;
use function in_array;
use function md5;
use function preg_match;

final class BotDetector implements RequestHandler
{
    public function __construct(private readonly RequestHandler $next) {
    }

    public function handle(Request $request): ResponseInterface
    {
        $userAgent = $request->serverParam('HTTP_USER_AGENT');
        $isAllowedBot = false;
        $ip = $request->serverParam('REMOTE_ADDR');
        $cfg = new BaseConfig();

        if ($this->isGoogleUserAgent($userAgent)) {
            if (!$this->isValidGooglebotDns($request->serverParam('REMOTE_ADDR'))) {
                $request->logger()->notice("{$ip} - Fake Googlebot rejected");

                return new Response('Fake bot rejected', 403);
            }

            $isAllowedBot = true;

            $request = $request->withAttribute('isAllowedBot', 'true');
        }

        if ($this->isBingUserAgent($userAgent)) {
            if (!$this->isValidBingbotDns($request->serverParam('REMOTE_ADDR'))) {
                $request->logger()->notice("{$ip} - Fake Bingbot rejected");

                return new Response('Fake bot rejected', 403);
            }

            $isAllowedBot = true;
            $request = $request->withAttribute('isAllowedBot', 'true');
        }

        // Cookies need to be enabled
        // This also reduces L7 DDoS effect as they can't guess the correct hash
        $correctCookieHash = md5($request->serverParam('REMOTE_ADDR') . (new RequestValidatorConfig())->cookieHashPepper());
        if (
            !$isAllowedBot &&
            !hash_equals($correctCookieHash, $request->cookie('request_key'))
        ) {
            $secure = $request->uri()->scheme() === 'https' ? ' Secure;' : '';

            return new EmptyResponse(
                307,
                [
                    'Set-Cookie' => ["request_key={$correctCookieHash}; Max-Age=86400; Path=/;{$secure}; HttpOnly; SameSite=Lax"],
                    'Location' => [(string)$request->uri()],
                ]
            );
        }

        $request = $request->withAttribute('requestKey', $correctCookieHash);

        $badAgents = [
            '^WordPress',
            '^WinHTTP',
            '^CRAZYWEBCRAWLER',
            '^okhttp',
            'AhrefsBot',
            '^Twitterbot',
            '^Python-urllib',
            '^python-requests',
            '^amppari',
            'RPT-HTTPClient',
            'OpenHoseBot',
            '^WebTarantula',
            'MSIECrawler',
            '^WeBoX',
            '^WebZIP',
            '^WordChampBot',
            '^Y!TunnelPro',
            'Snacktory',
            'NetcraftSurveyAgent',
            ' Daumoa',
            '^Natasha',
            'linkdexbot',
            'sqlmap',
            'PhantomJS',
            'MJ12bot',
            'TelegramBot',
            'SeznamBot',
            'coccocbot-web',
            'admantx-',
            '^SentiBot',
            'Qwantify',
            '^WNMCrawler',
            'Headless',
        ];

        if (preg_match('/(' . implode('|', $badAgents) . ')/', $userAgent)) {
            $request->logger()->notice("{$ip} - Bad bot rejected: '{$userAgent}'");

            return new Response('Bad bot rejected', 403);
        }

        return $this->next->handle($request);
    }

    private function isGoogleUserAgent(string $userAgent): bool
    {
        $googleUserAgents = [
            "APIs-Google (+https://developers.google.com/webmasters/APIs-Google.html)",
            "Mediapartners-Google",
            "Mozilla/5.0 (Linux; Android 5.0; SM-G920A) AppleWebKit (KHTML, like Gecko) Chrome Mobile Safari (compatible; AdsBot-Google-Mobile; +http://www.google.com/mobile/adsbot.html)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1 (compatible; AdsBot-Google-Mobile; +http://www.google.com/mobile/adsbot.html)",
            "AdsBot-Google (+http://www.google.com/adsbot.html)",
            "Googlebot-Image/1.0",
            "Googlebot-News",
            "Googlebot-Video/1.0",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "AdsBot-Google-Mobile-Apps",
            "FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.118 Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 Google Favicon",
            "Mozilla/5.0 (Linux; Android 8.0; Pixel 2 Build/OPD3.170816.012; DuplexWeb-Google/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Mobile Safari/537.36",
        ];

        $googleUserAgentsRegex = [
            "#^Mozilla/5\.0 AppleWebKit/537\.36 \(KHTML, like Gecko; compatible; Googlebot/2\.1; \+http://www\.google\.com/bot\.html\) Chrome/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ Safari/537\.36$#",
            "#^Mozilla/5\.0 \(Linux; Android 6\.0\.1; Nexus 5X Build/MMB29P\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ Mobile Safari/537\.36 \(compatible; Googlebot/2\.1; \+http://www\.google\.com/bot\.html\)$#",
            "# \(compatible; Mediapartners\-Google/2\.1; \+http://www\.google\.com/bot\.html\)$#",
            "# GoogleAdSenseInfeed\)#",
        ];

        if (in_array($userAgent, $googleUserAgents)) {
            return true;
        }

        foreach ($googleUserAgentsRegex as $regex) {
            if (preg_match($regex, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    private function isValidGooglebotDns(string $ip): bool
    {
        $reverseDns = gethostbyaddr($ip);
        if ($reverseDns === $ip) {
            return false;
        }

        if (!preg_match('/^.+\.google(bot)?\.com$/i', $reverseDns)) {
            return false;
        }

        if (gethostbyname($reverseDns) === $ip) {
            return true;
        }

        return false;
    }

    private function isBingUserAgent(string $userAgent): bool
    {
        $userAgents = [
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534+ (KHTML, like Gecko) BingPreview/1.0b",
            "Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko BingPreview/1.0b",
        ];

        $userAgentsRegex = [
            "#^Mozilla/5\.0 AppleWebKit/537\.36 \(KHTML, like Gecko; compatible; bingbot/2\.0; \+http://www\.bing\.com/bingbot\.htm\) Chrome/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ Safari/537\.36$#",
            "#^Mozilla/5\.0 AppleWebKit/537\.36 \(KHTML, like Gecko; compatible; bingbot/2\.0; \+http://www\.bing\.com/bingbot\.htm\) Chrome/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ Safari/537\.36 Edg/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$#",
            "#^Mozilla/5\.0 \(Linux; Android 6\.0\.1; Nexus 5X Build/MMB29P\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ Mobile Safari/537\.36 \(compatible; bingbot/2\.0; \+http://www\.bing\.com/bingbot\.htm\)$#",
            "#^Mozilla/5\.0 \(Linux; Android 6\.0\.1; Nexus 5X Build/MMB29P\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ Mobile Safari/537\.36 Edg/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ \(compatible; bingbot/2\.0; \+http://www\.bing\.com/bingbot\.htm\)$#",
        ];

        if (in_array($userAgent, $userAgents)) {
            return true;
        }

        foreach ($userAgentsRegex as $regex) {
            if (preg_match($regex, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    private function isValidBingbotDns(string $ip): bool
    {
        $reverseDns = gethostbyaddr($ip);
        if ($reverseDns === $ip) {
            return false;
        }

        if (!preg_match('/^.+\.search\.msn\.com$/i', $reverseDns)) {
            return false;
        }

        if (gethostbyname($reverseDns) === $ip) {
            return true;
        }

        return false;
    }
}