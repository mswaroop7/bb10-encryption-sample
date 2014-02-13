/*
 * EncryptedItem.h
 *
 *  Created on: Oct 24, 2013
 *      Author: swaroop.mahajan
 */

#ifndef ENCRYPTEDITEM_H_
#define ENCRYPTEDITEM_H_
 /**
  * Represents encrypted data and it's number of blocks
  */
class EncryptedItem {

private:
	/** encrypted text */
	unsigned char* cipherText ;
	/** block size of encryption of the cipher text*/
	int DES_BLOCK_SIZE ;

public:
	/**
	 * Constructor
	 *
	 * \param encryptedText is cipher text
	 * \param DES_BLOCK_SIZE is block size of the cipher text
	 */
	EncryptedItem(unsigned char*,int);

	/**
	 * Destructor
	 */
	virtual ~EncryptedItem();

	/**
	 * Gets cipher text
	 *
	 * \return cipherText is the encrypted text
	 */
	unsigned char* getCipherText() ;

	/**
	 * Gets the block size
	 *
	 * \return blocksize of the cipher text
	 */
	int getDESBlockSize() ;
};

#endif /* ENCRYPTEDITEM_H_ */
