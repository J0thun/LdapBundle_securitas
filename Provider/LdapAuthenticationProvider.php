<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

use IMAG\LdapBundle\Manager\LdapManagerUserInterface;
use IMAG\LdapBundle\Event\LdapUserEvent;
use IMAG\LdapBundle\Event\LdapEvents;
use IMAG\LdapBundle\User\LdapUserInterface;

class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
    private
        $userProvider,
        $ldapManager1,
        $ldapManager2,
        $dispatcher,
        $providerKey,
        $hideUserNotFoundExceptions
        ;

    /**
     * Constructor
     *
     * Please note that $hideUserNotFoundExceptions is true by default in order
     * to prevent a possible brute-force attack.
     *
     * @param UserProviderInterface    $userProvider
     * @param LdapManagerUserInterface $ldapManager1
     * @param LdapManagerUserInterface $ldapManager2
     * @param EventDispatcherInterface $dispatcher
     * @param string                   $providerKey
     * @param Boolean                  $hideUserNotFoundExceptions
     */
    public function __construct(
        UserProviderInterface $userProvider,
        AuthenticationProviderInterface $daoAuthenticationProvider,
        LdapManagerUserInterface $ldapManager1,
        EventDispatcherInterface $dispatcher = null,
        $providerKey,
        $hideUserNotFoundExceptions = true,
        LdapManagerUserInterface $ldapManager2
    )
    {
        $this->userProvider = $userProvider;
        $this->daoAuthenticationProvider = $daoAuthenticationProvider;
        $this->ldapManager1 = $ldapManager1;
        $this->ldapManager2 = $ldapManager2;
        $this->dispatcher = $dispatcher;
        $this->providerKey = $providerKey;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('Unsupported token');
        }

        try {
            $user = $this->userProvider
                ->loadUserByUsername($token->getUsername());
        } catch (UsernameNotFoundException $userNotFoundException) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $userNotFoundException);
            }

            throw $userNotFoundException;
        }

        if ($user instanceof LdapUserInterface) {
            return $this->ldapAuthenticate($user, $token);
        }

        if ($user instanceof UserInterface) {
            return $this->daoAuthenticationProvider->authenticate($token);
        }
    }

    /**
     * Authentication logic to allow Ldap user
     *
     * @param \IMAG\LdapBundle\User\LdapUserInterface  $user
     * @param TokenInterface $token
     *
     * @return \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken $token
     */
    private function ldapAuthenticate(LdapUserInterface $user, TokenInterface $token)
    {
        if (null !== $this->dispatcher) {
            $userEvent = new LdapUserEvent($user);
            try {
                $this->dispatcher->dispatch(LdapEvents::PRE_BIND, $userEvent);
            } catch (AuthenticationException $expt) {
                if ($this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials', 0, $expt);
                }

                throw $expt;
            }
        }

        // Essayez d'abord le premier LDAP manager
        if ($this->bind($user, $token, $this->ldapManager1)) {
            return $this->finalizeLdapAuthentication($user, $token, $userEvent);
        }

        // Si l'authentification échoue, essayez le deuxième LDAP manager
        if ($this->bind($user, $token, $this->ldapManager2)) {
            return $this->finalizeLdapAuthentication($user, $token, $userEvent);
        }
            
        if ($this->hideUserNotFoundExceptions) {
            throw new BadCredentialsException('Bad credentials');
        } else {
            throw new AuthenticationException('The LDAP authentication failed.');
        }
    }

    private function finalizeLdapAuthentication(LdapUserInterface $user, TokenInterface $token, LdapUserEvent $userEvent)
    {
        if (false === $user->getDn()) {
            $user = $this->reloadUser($user);
        }
    
        if (null !== $this->dispatcher) {
            $userEvent = new LdapUserEvent($user);
            try {
                $this->dispatcher->dispatch(LdapEvents::POST_BIND, $userEvent);
            } catch (AuthenticationException $authenticationException) {
                if ($this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials', 0, $authenticationException);
                }
    
                throw $authenticationException;
            }
        }
    
        $token = new UsernamePasswordToken($userEvent->getUser(), null, $this->providerKey, $userEvent->getUser()->getRoles());
        $token->setAttributes($token->getAttributes());
    
        return $token;
    }
    
    /**
     * Authenticate the user with LDAP bind.
     *
     * @param \IMAG\LdapBundle\User\LdapUserInterface  $user
     * @param TokenInterface $token
     *
     * @return boolean
     */
    private function bind(LdapUserInterface $user, TokenInterface $token, LdapManagerUserInterface $ldapManager)
    {
        $ldapManager
            ->setUsername($user->getUsername())
            ->setPassword($token->getCredentials());
    
        return (bool)$ldapManager->auth();
    }
    /**
     * Reload user with the username
     *
     * @param \IMAG\LdapBundle\User\LdapUserInterface $user
     * @return \IMAG\LdapBundle\User\LdapUserInterface $user
     */
    private function reloadUser(LdapUserInterface $user)
    {
        try {
            $user = $this->userProvider->refreshUser($user);
        } catch (UsernameNotFoundException $userNotFoundException) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $userNotFoundException);
            }

            throw $userNotFoundException;
        }

        return $user;
    }

    /**
     * Check whether this provider supports the given token.
     *
     * @param TokenInterface $token
     *
     * @return boolean
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken
            && $token->getProviderKey() === $this->providerKey;
    }
}
