<?php

namespace Sandstorm\NeosTwoFactorAuthentication\Domain\Repository;

use Exception;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\Doctrine\QueryResult;
use Neos\Flow\Persistence\Repository;
use Neos\Flow\Security\Account;
use ReflectionProperty;
use Sandstorm\NeosTwoFactorAuthentication\Domain\Model\SecondFactor;

/**
 * @Flow\Scope("singleton")
 *
 * @method QueryResult findByAccount(Account $account)
 */
class SecondFactorRepository extends Repository
{
    public function isEnabledForAccount(Account $account): bool
    {;
        $factors = $this->findByAccount($account);

        /** @var SecondFactor $factor */
        foreach ($factors as $factor) {
            $rp = new ReflectionProperty(SecondFactor::class, 'secret');
            if ($rp->isInitialized($factor)) {
                return true;
            }
        }

        return false;
    }
}
