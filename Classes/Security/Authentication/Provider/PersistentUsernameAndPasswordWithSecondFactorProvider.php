<?php

namespace Sandstorm\NeosTwoFactorAuthentication\Security\Authentication\Provider;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\Exception\IllegalObjectTypeException;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\PersistedUsernamePasswordProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use ReflectionProperty;
use Sandstorm\NeosTwoFactorAuthentication\Domain\Model\SecondFactor;
use Sandstorm\NeosTwoFactorAuthentication\Domain\Repository\SecondFactorRepository;
use Sandstorm\NeosTwoFactorAuthentication\Error\SecondFactorCreationRequiredException;
use Sandstorm\NeosTwoFactorAuthentication\Error\SecondFactorRequiredException;
use Sandstorm\NeosTwoFactorAuthentication\Security\Authentication\Token\UsernameAndPasswordWithSecondFactor;
use Sandstorm\NeosTwoFactorAuthentication\Service\TOTPService;

class PersistentUsernameAndPasswordWithSecondFactorProvider extends PersistedUsernamePasswordProvider
{

    /**
     * @Flow\InjectConfiguration(package="Sandstorm.NeosTwoFactorAuthentication", path="options.forceSecondFactorAuthentication")
     * @var bool
     */
    protected $forceSecondFactorAuthentication;

    /**
     * @var SecondFactorRepository
     * @Flow\Inject(lazy=false)
     */
    protected SecondFactorRepository $secondFactorRepository;

    public function getTokenClassNames()
    {
        return [UsernameAndPasswordWithSecondFactor::class];
    }

    public function authenticate(TokenInterface $authenticationToken)
    {
        // \Neos\Flow\Var_dump($authenticationToken);
        if (!($authenticationToken instanceof UsernameAndPasswordWithSecondFactor)) {
            throw new UnsupportedAuthenticationTokenException(sprintf('This provider cannot authenticate the given token. The token must implement %s', UsernameAndPasswordWithSecondFactor::class), 1217339840);
        }

        parent::authenticate($authenticationToken);

        $account = $authenticationToken->getAccount();

        if (!$account) {
            return;
        }

        // second factor was submitted, in this case username and password are not submitted
        if ($authenticationToken->secondFactorWasSubmitted()) {
            if ($this->enteredTokenMatchesAnySecondFactor($authenticationToken->getSecondFactor(), $account)) {
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                // prevent second factor form from appearing again by persisting second factor was authenticated
                $authenticationToken->setAuthenticatedWithSecondFactor(true);
            } else {
                // deny access again because second factor was invalid
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
                throw new SecondFactorRequiredException();
            }
        }

        if ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
            return;
        }

        if ($authenticationToken->getAuthenticationStatus() === TokenInterface::AUTHENTICATION_SUCCESSFUL) {
            if ($this->secondFactorRepository->isEnabledForAccount($account) && !$authenticationToken->isAuthenticatedWithSecondFactor()) {
                // deny access again because second factor is required
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
                // This exception gets caught inside the {@see SecondFactorRedirectMiddleware}
                throw new SecondFactorRequiredException();
            }
            // If we force second factor authentication and the user does not have 2fa enabled he is forced to create a token
            if (!$this->secondFactorRepository->isEnabledForAccount($account) && !$authenticationToken->isAuthenticatedWithSecondFactor() && $this->forceSecondFactorAuthentication) {
                // deny access again because second factor is required
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
                $secondFactorCreationRequiredException = new SecondFactorCreationRequiredException();
                $sessionIdentifier = $this->getSessionIdentifierForSecondTokenActivationByAccount($account);
                $secondFactorCreationRequiredException->setSessionIdentifier($sessionIdentifier);
                // This exception gets caught inside the {@see SecondFactorRedirectMiddleware}
                throw $secondFactorCreationRequiredException;
            }
        }
    }

    /**
     * Check if the given token matches any registered second factor
     *
     * @param string $enteredSecondFactor
     * @param Account $account
     * @return bool
     */
    protected function enteredTokenMatchesAnySecondFactor(string $enteredSecondFactor, Account $account): bool
    {
        /** @var SecondFactor[] $secondFactors */
        $secondFactors = $this->secondFactorRepository->findByAccount($account);
        foreach ($secondFactors as $secondFactor) {
            $isValid = TOTPService::checkIfOtpIsValid($secondFactor->getSecret(), $enteredSecondFactor);
            if ($isValid) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get a sessionIdentifier which is needed to enable 2fa
     * This identifier is bound to an account
     *
     * @param $account
     * @return string
     * @throws IllegalObjectTypeException
     */
    private function getSessionIdentifierForSecondTokenActivationByAccount($account)
    {

        $alreadyCreatedActivationToken = $this->getAlreadyCreatedActivationTokenByAccount($account);

        if ($alreadyCreatedActivationToken) {
            return $alreadyCreatedActivationToken;
        } else {
            $sessionIdentifier = bin2hex(random_bytes(32));
            $secondFactor = new SecondFactor();
            $secondFactor->setAccount($account);
            $secondFactor->setSessionIdentifier($sessionIdentifier);
            $secondFactor->setType(SecondFactor::TYPE_TOTP);
            $this->secondFactorRepository->add($secondFactor);
            $this->persistenceManager->persistAll();
            return $sessionIdentifier;
        }
    }


    /**
     * Check if there is an database entry with an already created sessionIdentifier which was created on another session
     *
     * @param $account
     * @return string|null
     */
    private function getAlreadyCreatedActivationTokenByAccount($account)
    {
        $secondFactors = $this->secondFactorRepository->findByAccount($account);
        if (count($secondFactors) > 0) {

            foreach ($secondFactors as $secondFactor) {
                $rp = new ReflectionProperty(SecondFactor::class, 'secret');
                if (!$rp->isInitialized($secondFactor)) {
                    return $secondFactor->getSessionIdentifier();
                }
            }

        }
        return null;
    }

}
