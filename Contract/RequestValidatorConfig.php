<?php
declare(strict_types=1);

namespace RequestValidator\Contract;

interface RequestValidatorConfig
{
    public function cookieHashPepper(): string;

    public function hCaptchaSiteKey(): string;

    public function hCaptchaSecretKey(): string;
}