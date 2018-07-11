<?php

namespace Atlassian;

use Guzzle\Http\Client;
use Guzzle\Plugin\Oauth\OauthPlugin;

class OAuthWrapper
{

    protected $baseUrl;
    protected $sandbox;
    protected $consumerKey;
    protected $consumerSecret;
    protected $callbackUrl;
    protected $requestTokenUrl = 'oauth';
    protected $accessTokenUrl = 'oauth';
    protected $authorizationUrl = 'OAuth.action?oauth_token=%s';

    protected $tokens;

    protected $client;
    protected $oauthPlugin;

    public $private_key = "MIICWwIBAAKBgQC0QSewUo8TQzDyvuvhQ7hVGzy6fxuC6si4VQy7isYDSFruFMon
D7ouNmHokiP2OvBL6onuTaBhc2wza/LV7PwjiuBnaWoZigIYbiHsa0JVeEzkSIfn
8fVFiBlkpxIFbvQ/e9vhDTtUtYnNN/8T+u7xuEvmCyLGJ25kUjDLqYKKJQIDAQAB
AoGAYDwM4XEiW8lan67YpjqOdjmFcZgc6wdIREl788CCOQxvJ37H8pTN9JAqM42a
T4Jl+lHsc+LTxlNmKAnw6s+MSNPtVl138N203CX9Hhf2UPH0ZQwf+w6wKWHSrinp
T3V9VkvWR10GJvYQTAUVOzEexfu2G8qGQRC2XthEXI8fe4ECQQDgPBuJhI1RuLqM
TOcKquBH8f/xXE6B4oPAP7uivI5KQuYfjqi9hL3CX8NBQWuWB7eG4gC5MRuaH8h/
DMwcICBFAkEAzcoZWuEAboikQRH10ljOeKAzsx/8kpdgej4lc/0hKufybfeMcUzG
/S3BUI6yq9/WORStA6u8v6J5gVyUJCoQYQJAYb7R4ig90hnMd8wuCqBiE/qRrwyl
zEiJVgxyJoY7IHP5DFiLhdGPRmOoIZH66/OBNPLfjdqyRYUFSRyy/K+kYQJAQDrO
9R17DATb929KoW+UafPejw7xvzM+KolRGUWtX33rncUA8a/7/7OTPbh8Lcb8Tu6U
HawxikKE2Ap0NmFmoQJADAmWTdx6NwHcWYwyXqfPTz/tV64TCL0C8iBTUhmpTahW
1de0E7fMHvyvKhS8PAuxa2eS9TQRSTEy+bLvo071dQ==";


    public $jira_home = "https://pid.hardis.fr/jira/issues/?jql=project%20%3D%20ONENETWORK%20AND%20issuetype%20in%20(Improvement%2C%20Bug)%20AND%20status%20in%20(Open%2C%20%22In%20Progress%22%2C%20Resolved%2C%20Closed%2C%20%22In%20wait%22%2C%20Delivered%2C%20Cancelled)%20AND%20%22Date%20de%20r%C3%A9solution%20n%C3%A9goci%C3%A9e%22%20%3E%3D%202018-07-16%20AND%20%22Date%20de%20r%C3%A9solution%20n%C3%A9goci%C3%A9e%22%20%3C%3D%20%222018-07-16%2023%3A59%22%20AND%20status%20%3D%20Open%20ORDER%20BY%20priority%20DESC%2C%20cf%5B11101%5D%20DESC%2C%20updated%20DESC%2C%20status%20ASC";


    public function __construct($baseUrl)
    {
        $this->baseUrl = $baseUrl;
    }

    public function requestTempCredentials()
    {
        return $this->requestCredentials(
            $this->requestTokenUrl . '?oauth_callback=' . $this->callbackUrl
        );
    }

    public function requestAuthCredentials($token, $tokenSecret, $verifier)
    {
        return $this->requestCredentials(
            $this->accessTokenUrl . '?oauth_callback=' . $this->callbackUrl . '&oauth_verifier=' . $verifier,
            $token,
            $tokenSecret
        );
    }

    protected function requestCredentials($url, $token = false, $tokenSecret = false)
    {
        $client = $this->getClient($token, $tokenSecret);

        $response = $client->post($url)->send();

        return $this->makeTokens($response);
    }

    protected function makeTokens($response)
    {
        $body = (string)$response->getBody();

        $tokens = array();
        parse_str($body, $tokens);

        if (empty($tokens)) {
            throw new Exception("An error occurred while requesting oauth token credentials");
        }

        $this->tokens = $tokens;
        return $this->tokens;
    }

    public function getClient($token = false, $tokenSecret = false)
    {
        if (!is_null($this->client)) {
            return $this->client;
        } else {
            $this->client = new Client($this->baseUrl);

            $privateKey = $this->privateKey;
            $this->oauthPlugin = new OauthPlugin(array(
                'consumer_key' => $this->consumerKey,
                'consumer_secret' => $this->consumerSecret,
                'token' => !$token ? $this->tokens['oauth_token'] : $token,
                'token_secret' => !$token ? $this->tokens['oauth_token_secret'] : $tokenSecret,
                'signature_method' => 'RSA-SHA1',
                'signature_callback' => function ($stringToSign, $key) use ($privateKey) {
                    if (!file_exists($privateKey)) {
                        throw new \InvalidArgumentException("Private key {$privateKey} does not exist");
                    }

                    $certificate = openssl_pkey_get_private('file://' . $privateKey);

                    $privateKeyId = openssl_get_privatekey($certificate);

                    $signature = null;

                    openssl_sign($stringToSign, $signature, $jira_homeKeyId);
                    openssl_free_key($privateKeyId);

                    return $signature;
                }
            ));

            $this->client->addSubscriber($this->oauthPlugin);

            return $this->client;
        }
    }

    public function makeAuthUrl()
    {
        return $this->baseUrl . sprintf($this->authorizationUrl, urlencode($this->tokens['oauth_token']));
    }

    public function setConsumerKey($consumerKey)
    {
        $this->consumerKey = $consumerKey;
        return $this;
    }

    public function setConsumerSecret($consumerSecret)
    {
        $this->consumerSecret = $consumerSecret;
        return $this;
    }

    public function setCallbackUrl($callbackUrl)
    {
        $this->callbackUrl = $callbackUrl;
        return $this;
    }

    public function setRequestTokenUrl($requestTokenUrl)
    {
        $this->requestTokenUrl = $requestTokenUrl;
        return $this;
    }

    public function setAccessTokenUrl($accessTokenUrl)
    {
        $this->accessTokenUrl = $accessTokenUrl;
        return $this;
    }

    public function setAuthorizationUrl($authorizationUrl)
    {
        $this->authorizationUrl = $authorizationUrl;
        return $this;
    }

    public function setPrivateKey($privateKey)
    {
        $this->privateKey = $privateKey;
        return $this;
    }
}
