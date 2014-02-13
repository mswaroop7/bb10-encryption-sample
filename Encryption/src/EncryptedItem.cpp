/*
 * EncryptedItem.cpp
 *
 *  Created on: Oct 24, 2013
 *      Author: swaroop.mahajan
 */

#include "EncryptedItem.h"

EncryptedItem::EncryptedItem(unsigned char* cipher, int blockSize) : cipherText(cipher){
	this->DES_BLOCK_SIZE = blockSize ;
}

EncryptedItem::~EncryptedItem() {
	// nothing to do
}

unsigned char* EncryptedItem::getCipherText() {
	return this->cipherText ;
}

int EncryptedItem::getDESBlockSize() {
	return this->DES_BLOCK_SIZE ;
}

