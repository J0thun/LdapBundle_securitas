<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException,
    Symfony\Component\Security\Core\Exception\UsernameNotFoundException,
    Symfony\Component\Security\Core\User\UserInterface,
    Symfony\Component\Security\Core\User\UserProviderInterface;

use IMAG\LdapBundle\Manager\LdapManagerUserInterface,
    IMAG\LdapBundle\User\LdapUserInterface;

/**
 * LDAP User Provider
 *
 * @author Boris Morel
 * @author Juti Noppornpitak <jnopporn@shiroyuki.com>
 */
class LdapUserProvider implements UserProviderInterface
{
    /**
     * @var \IMAG\LdapBundle\Manager\LdapManagerUserInterface
     */
    private $ldapManager1;

    /**
     * @var \IMAG\LdapBundle\Manager\LdapManagerUserInterface
     */
    private $ldapManager2;

    /**
     * @var string
     */
    private $bindUsernameBefore;

    /**
     * The class name of the User model
     * @var string
     */
    private $userClass;

    /**
     * Constructor
     *
     * @param \IMAG\LdapBundle\Manager\LdapManagerUserInterface $ldapManager1
     * @param \IMAG\LdapBundle\Manager\LdapManagerUserInterface $ldapManager2
     * @param bool|string                                       $bindUsernameBefore
     * @param string                                            $userClass
     */
    public function __construct(LdapManagerUserInterface $ldapManager1, LdapManagerUserInterface $ldapManager2, $bindUsernameBefore = false, $userClass)
    {
        $this->ldapManager1 = $ldapManager1;
        $this->ldapManager2 = $ldapManager2;
        $this->bindUsernameBefore = $bindUsernameBefore;
        $this->userClass = $userClass;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        // Throw the exception if the username is not provided.
        if (empty($username)) {
            throw new UsernameNotFoundException('The username is not provided.');
        }

        if (true === $this->bindUsernameBefore) {
            $ldapUser = $this->simpleUser($username);
        } else {
            $ldapUser = $this->anonymousSearch($username);
        }

        return $ldapUser;
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof LdapUserInterface) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return is_subclass_of($class, '\IMAG\LdapBundle\User\LdapUserInterface');
    }

    private function simpleUser($username)
    {
        $ldapUser = new $this->userClass;
        $ldapUser->setUsername($username);

        return $ldapUser;
    }

    private function anonymousSearch($username)
    {
        // Throw the exception if the username is not found.
        $ldapManager1 = $this->ldapManager1;
        $ldapManager2 = $this->ldapManager2;

        if (!$ldapManager1->exists($username) && !$ldapManager2->exists($username)) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found in both LDAP servers', $username));
        }

        $lm = null;
        if ($ldapManager1->exists($username)) {
            $lm = $ldapManager1
                ->setUsername($username)
                ->doPass();
        } elseif ($ldapManager2->exists($username)) {
            $lm = $ldapManager2
                ->setUsername($username)
                ->doPass();
        }

        $ldapUser = new $this->userClass;

        $ldapUser
            ->setUsername($lm->getUsername())
            ->setEmail($lm->getEmail())
            ->setRoles($lm->getRoles())
            ->setDn($lm->getDn())
            ->setCn($lm->getCn())
            ->setAttributes($lm->getAttributes())
            ->setGivenName($lm->getGivenName())
            ->setSurname($lm->getSurname())
            ->setDisplayName($lm->getDisplayName())
            ;

        return $ldapUser;
    }
}
