<?php

namespace Sandstorm\NeosTwoFactorAuthentication\Error;

/**
 * This Exception get thrown inside the authentication provider to trigger a redirect by the middleware.
 * This is to redirect the user to the form for the second factor.
 */
class SecondFactorCreationRequiredException extends \Exception
{

    protected string $sessionIdentifier;

    /**
     * @return string
     */
    public function getSessionIdentifier(): string
    {
        return $this->sessionIdentifier;
    }

    /**
     * @param string $sessionIdentifier
     */
    public function setSessionIdentifier(string $sessionIdentifier): void
    {
        $this->sessionIdentifier = $sessionIdentifier;
    }

}
