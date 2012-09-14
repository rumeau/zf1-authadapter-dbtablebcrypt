<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 * @package   Zend_Crypt
 */

/**
 * Bcrypt algorithm using crypt() function of PHP
 *
 * @category   Zend
 * @package    Zend_Crypt
 */
class Jr_Crypt_Password_Bcrypt implements Jr_Crypt_Password_PasswordInterface
{
    const MIN_SALT_SIZE = 16;

    /**
     * @var string
     */
    protected $cost = '10';

    /**
     * @var string
     */
    protected $salt;

    /**
     * Constructor
     *
     * @param array $options
     * @throws Jr_Crypt_Exception
     */
    public function __construct($options = array())
    {
        if (!empty($options)) {
            if (!is_array($options)) {
                throw new Jr_Crypt_Exception(
                	'The options parameter must be an array'
                );
            }
            foreach ($options as $key => $value) {
                switch (strtolower($key)) {
                    case 'salt':
                        $this->setSalt($value);
                        break;
                    case 'cost':
                        $this->setCost($value);
                        break;
                }
            }
        }
    }

    /**
     * Bcrypt
     *
     * @param  string $password
     * @throws Jr_Crypt_Exception
     * @return string
     */
    public function create($password)
    {
        if (empty($this->salt)) {
            $salt = Jr_Math_Rand::getBytes(self::MIN_SALT_SIZE);
        } else {
            $salt = $this->salt;
        }
        $salt64 = substr(str_replace('+', '.', base64_encode($salt)), 0, 22);
        /**
         * Check for security flaw in the bcrypt implementation used by crypt()
         * @see http://php.net/security/crypt_blowfish.php
         */
        if (version_compare(PHP_VERSION, '5.3.7') >= 0) {
            $prefix = '$2y$';
        } else {
            $prefix = '$2a$';
            // check if the password contains 8-bit character
            if (preg_match('/[\x80-\xFF]/', $password)) {
                throw new Jr_Crypt_Exception(
                    'The bcrypt implementation used by PHP can contains a security flaw ' .
                    'using password with 8-bit character. ' .
                    'We suggest to upgrade to PHP 5.3.7+ or use passwords with only 7-bit characters'
                );
            }
        }
        $hash = crypt($password, $prefix . $this->cost . '$' . $salt64);
        if (strlen($hash) <= 13) {
            throw new Jr_Crypt_Exception('Error during the bcrypt generation');
        }
        return $hash;
    }

    /**
     * Verify if a password is correct against an hash value
     *
     * @param  string $password
     * @param  string $hash
     * @return boolean
     */
    public function verify($password, $hash)
    {
        return ($hash === crypt($password, $hash));
    }

    /**
     * Set the cost parameter
     *
     * @param  integer|string $cost
     * @throws Jr_Crypt_Exception
     * @return Bcrypt
     */
    public function setCost($cost)
    {
        if (!empty($cost)) {
            $cost = (int)$cost;
            if ($cost < 4 || $cost > 31) {
                throw new Jr_Crypt_Exception(
                    'The cost parameter of bcrypt must be in range 04-31'
                );
            }
            $this->cost = sprintf('%1$02d', $cost);
        }
        return $this;
    }

    /**
     * Get the cost parameter
     *
     * @return string
     */
    public function getCost()
    {
        return $this->cost;
    }

    /**
     * Set the salt value
     *
     * @param  string $salt
     * @throws Jr_Crypt_Exception
     * @return Bcrypt
     */
    public function setSalt($salt)
    {
        if (strlen($salt) < self::MIN_SALT_SIZE) {
            throw new Jr_Crypt_Exception(
                'The length of the salt must be at lest ' . self::MIN_SALT_SIZE . ' bytes'
            );
        }
        $this->salt = $salt;
        return $this;
    }

    /**
     * Get the salt value
     *
     * @return string
     */
    public function getSalt()
    {
        return $this->salt;
    }
}
