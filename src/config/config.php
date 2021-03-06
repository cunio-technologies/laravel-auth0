<?php

return array(

    /*
    |--------------------------------------------------------------------------
    |   Your openid domain
    |--------------------------------------------------------------------------
    |   As set in the openid administration page
    |
    */
    'domain'        => env( 'OPENID_DOMAIN' ),

    /*
    |--------------------------------------------------------------------------
    |   Your APP id
    |--------------------------------------------------------------------------
    |   As set in the openid administration page
    |
    */
    'client_id'     => env( 'OPENID_CLIENT_ID' ),

    /*
    |--------------------------------------------------------------------------
    |   Your APP secret
    |--------------------------------------------------------------------------
    |   As set in the openid administration page
    |
    */
    'client_secret' => env( 'OPENID_CLIENT_SECRET' ),

    /*
     |--------------------------------------------------------------------------
     |   The redirect URI
     |--------------------------------------------------------------------------
     |   Should be the same that the one configure in the route to handle the
     |   'OpenID\Login\OpenIDController@callback'
     |
     */
    'redirect_uri'  => env( 'APP_URL' ) . '/openid/callback',

    /*
    |--------------------------------------------------------------------------
    |   Persistence Configuration
    |--------------------------------------------------------------------------
    |   persist_user            (Boolean) Optional. Indicates if you want to persist the user info, default true
    |   persist_access_token    (Boolean) Optional. Indicates if you want to persist the access token, default false
    |   persist_id_token        (Boolean) Optional. Indicates if you want to persist the id token, default false
    |
    */
    'persist_user' => true,
    'persist_access_token' => false,
    'persist_id_token' => false,

    /*
    |--------------------------------------------------------------------------
    |   The authorized token issuers
    |--------------------------------------------------------------------------
    |   This is used to verify the decoded tokens when using RS256
    |
    */
    'authorized_issuers'  => [ env( 'OPENID_DOMAIN' ) ],

    /*
    |--------------------------------------------------------------------------
    |   The authorized token audiences
    |--------------------------------------------------------------------------
    |
    */
    // 'api_identifier'  => '',

    /*
    |--------------------------------------------------------------------------
    |   The secret format
    |--------------------------------------------------------------------------
    |   Used to know if it should decode the secret when using HS256
    |
    */
    'secret_base64_encoded'  => false,

    /*
    |--------------------------------------------------------------------------
    |   Supported algorithms
    |--------------------------------------------------------------------------
    |   Token decoding algorithms supported by your API
    |
    */
    'supported_algs'        => [ 'RS256' ],

    /*
    |--------------------------------------------------------------------------
    |   Guzzle Options
    |--------------------------------------------------------------------------
    |   guzzle_options    (array) optional. Used to specify additional connection options e.g. proxy settings
    |
    */
    // 'guzzle_options' => []
);
