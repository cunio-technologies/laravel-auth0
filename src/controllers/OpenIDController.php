<?php

namespace OpenID\Login;

use OpenID\Login\Contract\OpenIDUserRepository;
use Illuminate\Routing\Controller;

class OpenIDController extends Controller
{
    /**
     * @var OpenIDUserRepository
     */
    protected $userRepository;

    /**
     * OpenIDController constructor.
     *
     * @param OpenIDUserRepository $userRepository
     */
    public function __construct(OpenIDUserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    /**
     * Callback action that should be called by auth0, logs the user in.
     */
    public function callback()
    {
        // Get a handle of the OpenID service (we don't know if it has an alias)
        $service = \App::make('openid');

        // Try to get the user information
        $profile = $service->getUser();

        // Get the user related to the profile
        $auth0User = $this->userRepository->getUserByUserInfo($profile);

        if ($auth0User) {
            // If we have a user, we are going to log them in, but if
            // there is an onLogin defined we need to allow the Laravel developer
            // to implement the user as they want an also let them store it.
            if ($service->hasOnLogin()) {
                $user = $service->callOnLogin($auth0User);
            } else {
                // If not, the user will be fine
                $user = $auth0User;
            }
            \Auth::login($user, $service->rememberUser());
        }

        return \Redirect::intended('/');
    }
}
