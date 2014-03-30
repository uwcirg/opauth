<?php
/**
 * Opauth
 * Multi-provider authentication framework for PHP
 *
 * @copyright    Copyright © 2014 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @license      MIT License
 */
namespace Opauth\Opauth;

/**
 * Opauth Strategy
 * Individual strategies are to be extended from this class
 *
 */
abstract class AbstractStrategy implements StrategyInterface
{

    /**
     * Compulsory config keys, listed as numeric indexed arrays
     * eg. array('app_id', 'app_secret');
     */
    public $expects = array();

    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array();

    /**
     * Configurations and settings unique to a particular strategy
     */
    protected $strategy = array();

    /**
     * Key for $_SESSION data
     *
     * @var string
     */
    protected $sessionKey = '_opauth_data';

    /**
     * Map response from raw data
     *
     * @var array
     */
    protected $responseMap = array();

    /**
     *
     * @var Callback url which is called after request
     */
    protected $callbackUrl;

    /**
     * Http client transport class
     *
     * @var TransportInterface
     */
    protected $http;

    /**
     * Constructor
     *
     * @param array $config Strategy-specific configuration
     * @param string $callbackUrl Absolute url which is called on receiving the callback
     * @param TransportInterface $transport
     */
    public function __construct($config, $callbackUrl, $transport)
    {
        $this->setUp($config);
        $this->callbackUrl($callbackUrl);
        $this->setTransport($transport);

        $this->responseMap = $this->addParams(array('responseMap'), $this->responseMap);

        foreach ($this->strategy as $key => $value) {
            $this->strategy[$key] = $this->envReplace($value, $this->strategy);
        }
    }

    /**
     * Sets up defaults, configs and checks for required keys
     *
     * @param array $config
     */
    protected function setup($config = array())
    {
        $this->setValues($this->defaults);
        $this->setValues($config);
        $this->checkExpected();
    }

    /**
     * Getter/setter for the complete callbackurl
     *
     * @param null|string $url Null will get, string will set callbackUrl
     * @return string
     */
    public function callbackUrl($url = null)
    {
        if ($url) {
            $this->callbackUrl = $url;
        }
        return $this->callbackUrl;
    }

    /**
     * Set transport class
     *
     * @param \Opauth\Opauth\TransportInterface $transport
     */
    public function setTransport(TransportInterface $transport)
    {
        $this->http = $transport;
    }

    /**
     * Get transport class
     *
     * @return \Opauth\Opauth\TransportInterface $transport
     */
    public function getTransport()
    {
        return $this->http;
    }

    /**
     * Getter/setter method for session data
     *
     * @param array $data Array to write or null to read
     * @return array Session data
     */
    protected function sessionData($data = null)
    {
        if (!session_id()) {
            session_start();
        }
        $key = $this->sessionKey . $this->strategy['provider'];
        if (!$data) {
            $data = $_SESSION[$key];
            unset($_SESSION[$key]);
            return $data;
        }
        return $_SESSION[$key] = $data;
    }

    /**
     * Adds strategy config values to params array if set.
     * $configKeys array may contain string values, or key => value pairs
     * key for the strategy key, value for the params key to set
     *
     * @param array $configKeys
     * @param array $params
     * @return array
     */
    protected function addParams($configKeys, $params = array())
    {
        foreach ($configKeys as $configKey => $paramKey) {
            if (is_numeric($configKey)) {
                $configKey = $paramKey;
            }
            if (isset($this->strategy[$configKey])) {
                $params[$paramKey] = $this->strategy[$configKey];
            }
        }
        return $params;
    }

    /**
     * Response callback
     *
     * More info: https://github.com/uzyn/opauth/wiki/Auth-response
     *
     * @param string $raw Raw response from Oauth provider
     * @return Response
     */
    protected function response($raw)
    {
        $response = new Response($this->strategy['provider'], $raw);
        $response->setMap($this->responseMap);
        return $response;
    }

    /**
     * Throws OpauthException from strategy
     *
     * More info: https://github.com/uzyn/opauth/wiki/Auth-response#wiki-error-response
     *
     * @param string $message User-friendly error message (eg. User denied access.)
     * @param string $code Error code (eg. access_denied)
     * @param mixed $raw Raw data to help in debug, usually raw HTTP response from provider
     */
    protected function error($message, $code, $raw = null) {
        throw new OpauthException($message, $code, $this->strategy['provider'], $raw);
    }

    /**
     * Loads strategy values from default configs
     */
    protected function setValues($values = array())
    {
        foreach ($values as $key => $value) {
            $this->value($key, $value);
        }
    }

    /**
     * Getter/setter for strategy keys
     *
     * @param string $key Configuration key to be loaded
     * @param string $default Default value for the configuration key if none is set by the user
     * @return mixed The loaded value
     */
    protected function value($key, $default = null)
    {
        if (!isset($this->strategy[$key]) && $default === null) {
            return null;
        } elseif ($default !== null) {
            $this->strategy[$key] = $default;
        }
        return $this->strategy[$key];
    }

    /**
     * Check expected strategy keys
     *
     * @return true If all keys are present
     * @throws \Exception
     */
    protected function checkExpected()
    {
        foreach ($this->expects as $key) {
            if (!$this->hasKey($key)) {
                return $this->error(get_class($this) . " config parameter for \"$key\" expected.", 'missing_parameter', $this);
            }
        }
        return true;
    }

    /**
     * Checks if strategy value is set
     *
     * @param string $key Expected configuration key
     * @param string $not Value should not match this
     * @return boolean
     */
    protected function hasKey($key, $not = null)
    {
        if (!isset($this->strategy[$key]) || $this->strategy[$key] === $not) {
            return false;
        }
        return true;
    }

    /**
     * Recursively converts object into array
     * Basically get_object_vars, but recursive.
     *
     * @param mixed $obj Object
     * @return array Array of object properties
     */
    public function recursiveGetObjectVars($obj)
    {
        $arr = array();
        $_arr = is_object($obj) ? get_object_vars($obj) : $obj;

        foreach ($_arr as $key => $val) {
            $val = (is_array($val) || is_object($val)) ? self::recursiveGetObjectVars($val) : $val;

            // Transform boolean into 1 or 0 to make it safe across all Opauth HTTP transports
            if (is_bool($val)) {
                $val = ($val) ? 1 : 0;
            }

            $arr[$key] = $val;
        }

        return $arr;
    }

    /**
     * Replace defined env values enclosed in {} with values from $dictionary
     *
     * @param string $value Input string
     * @param array $dictionary Dictionary to lookup values from
     * @return string String substituted with value from dictionary, if applicable
     */
    public function envReplace($value, $dictionary)
    {
        if (is_string($value) && preg_match_all('/{([A-Za-z0-9-_]+)}/', $value, $matches)) {
            foreach ($matches[1] as $key) {
                if (array_key_exists($key, $dictionary)) {
                    $value = str_replace('{' . $key . '}', $dictionary[$key], $value);
                }
            }
            return $value;
        }
        return $value;
    }
}
