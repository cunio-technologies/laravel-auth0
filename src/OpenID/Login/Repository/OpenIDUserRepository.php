<?php

namespace OpenID\Login\Repository;

use OpenID\Login\OpenIDUser;
use OpenID\Login\OpenIDJWTUser;
use OpenID\Login\Contract\OpenIDUserRepository as OpenIDUserRepositoryContract;

class OpenIDUserRepository implements OpenIDUserRepositoryContract
{
    /**
     * @param \OpenID\Login\Contract\stdClass $jwt
     *
     * @return OpenIDJWTUser
     */
    public function getUserByDecodedJWT($jwt)
    {
        return new OpenIDJWTUser($jwt);
    }

    /**
     * @param array $userInfo
     *
     * @return OpenIDUser
     */
    public function getUserByUserInfo($userInfo)
    {
        return new OpenIDUser($userInfo['profile'], $userInfo['accessToken']);
    }

    /**
     * @param \OpenID\Login\Contract\the $identifier
     *
     * @return OpenIDUser|\Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function getUserByIdentifier($identifier)
    {
        // Get the user info of the user logged in (probably in session)
        $user = \App::make('openid')->getUser();

        if ($user === null) {
            return;
        }

        // Build the user
        $auth0User = $this->getUserByUserInfo($user);

        // It is not the same user as logged in, it is not valid
        if ($auth0User && $auth0User->getAuthIdentifier() == $identifier) {
            return $auth0User;
        }
    }
}
