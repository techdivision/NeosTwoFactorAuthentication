<?php

namespace Sandstorm\NeosTwoFactorAuthentication\Http\Middleware;

use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Sandstorm\NeosTwoFactorAuthentication\Error\SecondFactorCreationRequiredException;
use Sandstorm\NeosTwoFactorAuthentication\Error\SecondFactorRequiredException;

class SecondFactorRedirectMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $next): ResponseInterface
    {
        try {
            return $next->handle($request);
        } catch (SecondFactorRequiredException $exception) {
            return new Response(303, [
                'Location' => '/neos/two-factor-login'
            ]);
        } catch (SecondFactorCreationRequiredException $exception) {
            return new Response(303, [
                'Location' => '/neos/enable-two-factor-login/index?identifier=' . $exception->getSessionIdentifier()
            ]);
        }
    }
}
