/*
 * EncryptionService.h
 *
 *  Created on: Oct 22, 2013
 *      Author: swaroop.mahajan
 */

#ifndef ENCRYPTIONSERVICE_H_
#define ENCRYPTIONSERVICE_H_

#include <hudes.h>
#include <QString>
#include <EncryptedItem.h>
/**
 *  Performs encryption and decryption of given String
 */
class EncryptionService {

private:
	/** global context for DES encryption */
	sb_GlobalCtx globalCtx ;
	/** DES encryption paramater for configuring DES behaviour */
	sb_Params desParams ;
	/** DES encryptionKey for encryption */
	sb_Key desKey ;
	/** DES Context encryption */
	sb_Context desContext ;
	/** Initial vector for encryption */
	unsigned char iv[16];
	/** key for encryption */
	static const QString encryptionKey ;

private:
	/**
	 * Creates a global context initialized with default implementations
	 */
	void createGlobalCtx() ;

	/**
	 * Enables support for DES functions from the GSE56 software provider.
	 */
	void registerDESContext() ;

	/**
	 * Initializes the module and performs a series of self-tests
	 * to ensure the integrity of the module and correct operation of its
	 * cryptographic algorithms.
	 */
	void initDESContext() ;

	/**
	 * Decides behavior of the DES encryption
	 * Sets the type, mode, parity for the DES encryption
	 */
	void createDESParams() ;

	/**
	 * Creates the key for the DES encryption
	 */
	void createDESKey() ;

	/**
	 * Creates context for DES encryption
	 */
	void createDESContext() ;

	/**
	 * Converts QString to unsigned char*
	 *
	 * \param convertString is the to be converted into unsigned char*
	 *
	 * \return covertedString into unsigned char*
	 */
	unsigned char* convertToUStr(QString) ;

	/**
	 * Finds the length of the unsigned char*
	 *
	 * \param string whose length is to be measured
	 *
	 * \return length of the unsigned char*
	 */
	int ustrlen(unsigned char*) ;

public:
	/**
	 * Constructor
	 */
	EncryptionService();

	/**
	 * Destructor
	 */
	virtual ~EncryptionService();

	/**
	 * Encrypts given string using DES algorithm
	 *
	 * \param plainText is the string to be encrypted
	 *
	 * \return EncryptedItem containing encrypted string and DES_BLOCK_SIZE
	 * 						 for the encyption
	 */
	EncryptedItem encryptData(QString) ;

	/**
	 * Decrypts given EncryptedItem using DES algorithm
	 *
	 * \param encryptedItem containing encrypted string and DES_BLOCK_SIZE
	 * 						for the encyption
	 *
	 * \return plainText is decrypted plain text
	 */
	QString decryptData(EncryptedItem) ;
};

#endif /* ENCRYPTIONSERVICE_H_ */
