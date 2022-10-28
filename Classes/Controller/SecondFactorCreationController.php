<?php

namespace Sandstorm\NeosTwoFactorAuthentication\Controller;

/*
 * This file is part of the Sandstorm.NeosTwoFactorAuthentication package.
 */

use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;
use Neos\Error\Messages\Message;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Mvc\FlashMessage\FlashMessageService;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Session\Exception\SessionNotStartedException;
use Neos\Flow\Session\SessionManagerInterface;
use Neos\Fusion\View\FusionView;
use Neos\Neos\Domain\Repository\DomainRepository;
use Neos\Neos\Domain\Repository\SiteRepository;
use Sandstorm\NeosTwoFactorAuthentication\Domain\Model\SecondFactor;
use Sandstorm\NeosTwoFactorAuthentication\Domain\Repository\SecondFactorRepository;
use Sandstorm\NeosTwoFactorAuthentication\Service\TOTPService;

class SecondFactorCreationController extends ActionController
{

    /**
     * @var string
     */
    protected $defaultViewObjectName = FusionView::class;

    /**
     * @var SecurityContext
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @var AccountRepository
     * @Flow\Inject
     */
    protected $accountRepository;

    /**
     * @var AuthenticationManagerInterface
     * @Flow\Inject
     */
    protected $authenticationManager;

    /**
     * @var DomainRepository
     * @Flow\Inject
     */
    protected $domainRepository;

    /**
     * @Flow\Inject
     * @var SiteRepository
     */
    protected $siteRepository;

    /**
     * @Flow\Inject
     * @var FlashMessageService
     */
    protected $flashMessageService;

    /**
     * @Flow\Inject
     * @var SessionManagerInterface
     */
    protected $sessionManager;

    /**
     * @var SecondFactorRepository
     * @Flow\Inject
     */
    protected $secondFactorRepository;

    /**
     * @Flow\SkipCsrfProtection
     * @Flow\Session(autoStart=true)
     * @throws SessionNotStartedException
     */
    public function indexAction(string $identifier)
    {
        /** @var SecondFactor $secondFactor */
        $secondFactor = $this->secondFactorRepository->findOneBySessionIdentifier($identifier);

        if ($secondFactor) {
            /** @var Account $account */
            $account = $secondFactor->getAccount();
            $username = $account->getAccountIdentifier();
        } else {
            $this->sessionManager->getCurrentSession()->destroy();
            $this->redirect('index', 'Login', 'Neos.Neos');
        }

        $otp = TOTPService::generateNewTotp();
        $secret = $otp->getSecret();
        $currentDomain = $this->domainRepository->findOneByActiveRequest();
        $currentSite = $currentDomain !== null ? $currentDomain->getSite() : $this->siteRepository->findDefault();
        $currentSiteName = $currentSite->getName();
        $urlEncodedSiteName = urlencode($currentSiteName);
        $oauthData = "otpauth://totp/$username?secret=$secret&period=30&issuer=$urlEncodedSiteName";
        $qrCode = (new QRCode(new QROptions([
            'outputType' => QRCode::OUTPUT_MARKUP_SVG
        ])))->render($oauthData);

        $this->view->assignMultiple([
            'secret' => $secret,
            'sessionIdentifier' => $identifier,
            'qrCode' => $qrCode,
            'flashMessages' => $this->flashMessageService->getFlashMessageContainerForRequest($this->request)->getMessagesAndFlush(),
        ]);
    }

    /**
     * save the registered second factor
     */
    public function createAction(string $secret, string $secondFactorFromApp, string $identifier)
    {
        // Check if the given 2FA token is valid
        $isValid = TOTPService::checkIfOtpIsValid($secret, $secondFactorFromApp);

        // Redirect to start when token is not valid
        if (!$isValid) {
            $this->addFlashMessage('Submitted OTP was not correct, please rescan the QR code and retry', '', Message::SEVERITY_WARNING);
            $this->redirect('index', null, null, ['identifier' => $identifier]);
        }

        // Update second factor in database
        /** @var SecondFactor $secondFactor */
        $secondFactor = $this->secondFactorRepository->findOneBySessionIdentifier($identifier);
        $secondFactor->setSecret($secret);
        $secondFactor->setType(SecondFactor::TYPE_TOTP);
        $secondFactor->setSessionIdentifier(null);
        $this->secondFactorRepository->update($secondFactor);
        $this->persistenceManager->persistAll();

        // Redirect to the neos login page
        $this->addFlashMessage('Successfully created otp');
        $this->redirect('index', 'Login', 'Neos.Neos');
    }

}
