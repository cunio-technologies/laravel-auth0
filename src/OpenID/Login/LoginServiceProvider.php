<?php

namespace OpenID\Login;

use Illuminate\Support\ServiceProvider;

class LoginServiceProvider extends ServiceProvider {

    const PROVIDER_NAME = 'openid';

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     */
    public function boot()
    {
        \Auth::provider(self::PROVIDER_NAME, function ($app, array $config) {
            return $app->make(OpenIDUserProvider::class);
        });

        $this->publishes([
            __DIR__.'/../../config/config.php' => config_path('openid.php'),
        ]);

        $laravel = app();
    }

    /**
     * Register the service provider.
     */
    public function register()
    {
        // Bind the auth0 name to a singleton instance of the OpenID Service
        $this->app->singleton(self::PROVIDER_NAME, function () {
          return new OpenIDService();
        });

        // When Laravel logs out, logout the auth0 SDK trough the service
        \Event::listen('auth.logout', function () {
            \App::make(self::PROVIDER_NAME)->logout();
        });
        \Event::listen('user.logout', function () {
            \App::make(self::PROVIDER_NAME)->logout();
        });
        \Event::listen('Illuminate\Auth\Events\Logout', function () {
            \App::make(self::PROVIDER_NAME)->logout();
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return array();
    }
}
