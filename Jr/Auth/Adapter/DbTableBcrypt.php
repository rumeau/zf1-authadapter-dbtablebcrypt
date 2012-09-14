<?php

class Jr_Auth_Adapter_DbTableBcrypt extends Zend_Auth_Adapter_DbTable
{
    protected $_saltColumn = 'salt';
    
	/**
     * _authenticateCreateSelect() - This method creates a Zend_Db_Select object that
     * is completely configured to be queried against the database.
     *
     * @return Zend_Db_Select
     */
    protected function _authenticateCreateSelect()
    {
        // get select
        $dbSelect = clone $this->getDbSelect();
        $dbSelect->from($this->_tableName, array('*'))
                 ->where($this->_zendDb->quoteIdentifier($this->_identityColumn, true) . ' = ?', $this->_identity);

        return $dbSelect;
    }
    
    /**
     * authenticate() - defined by Zend_Auth_Adapter_Interface.  This method is called to
     * attempt an authentication.  Previous to this call, this adapter would have already
     * been configured with all necessary information to successfully connect to a database
     * table and attempt to find a record matching the provided identity.
     *
     * @throws Zend_Auth_Adapter_Exception if answering the authentication query is impossible
     * @return Zend_Auth_Result
     */
    public function authenticate()
    {
    	$this->_authenticateSetup();
    	$dbSelect = $this->_authenticateCreateSelect();
    	$resultIdentities = $this->_authenticateQuerySelect($dbSelect);
    
    	if ( ($authResult = $this->_authenticateValidateResultSet($resultIdentities)) instanceof Zend_Auth_Result) {
    		return $authResult;
    	}
    
    	$authResult = $this->_authenticateValidateResult(array_shift($resultIdentities));
    	return $authResult;
    }
    
    /**
     * _authenticateValidateResult() - This method attempts to validate that
     * the record in the resultset is indeed a record that matched the
     * identity provided to this adapter.
     *
     * @param array $resultIdentity
     * @return Zend_Auth_Result
     */
    protected function _authenticateValidateResult($resultIdentity)
    {
        $bcrypt = new Jr_Crypt_Password_Bcrypt();
        
        // Compare DB Hash against User generated hash
        if (!$bcrypt->verify($this->_credential, $resultIdentity[$this->_credentialColumn])) {
    		$this->_authenticateResultInfo['code'] = Zend_Auth_Result::FAILURE_CREDENTIAL_INVALID;
    		$this->_authenticateResultInfo['messages'][] = 'Supplied credential is invalid.';
    		return $this->_authenticateCreateAuthResult();
    	}

    	unset($resultIdentity[$this->_credentialColumn], $resultIdentity[$this->_saltColumn]);
    	$this->_resultRow = $resultIdentity;
    
    	$this->_authenticateResultInfo['code'] = Zend_Auth_Result::SUCCESS;
    	$this->_authenticateResultInfo['messages'][] = 'Authentication successful.';
    	return $this->_authenticateCreateAuthResult();
    }
}