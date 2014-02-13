/*
 * EncryptionService.cpp
 *
 *  Created on: Oct 22, 2013
 *      Author: swaroop.mahajan
 */

#include "EncryptionService.h"
#include <string.h>
#include <huctx.h>
#include <hugse56.h>
#include <sbdef.h>
#include <QString>
#include <QDebug>
#include <sbreturn.h>
#include <algorithm>
#include <string>

using namespace std ;

const QString EncryptionService::encryptionKey = "$pringCorebridge123" ;

EncryptionService::EncryptionService(){
	// initialization of the iv
	iv[0] = 90 ;
	iv[1] = 66 ;
	iv[2] = -33 ;
	iv[3] = 66 ;
	iv[4] = 120 ;
	iv[5] = -67 ;
	iv[6] = -42 ;
	iv[7] = -99 ;
	iv[8] = 98 ;
	iv[9] = -7 ;
	iv[10] = -73 ;
	iv[11] = -10 ;
	iv[12] = -60 ;
	iv[13] = -109 ;
	iv[14] = -107 ;
	iv[15] = -125 ;

	// create gloabal context
	this->createGlobalCtx() ;
	// registers global context
	this->registerDESContext() ;
	// initializes global context
	this->initDESContext() ;
	// create DES params
	this->createDESParams() ;
	// create DES key
	this->createDESKey() ;
	// create DES key
	this->createDESContext() ;
}

void EncryptionService::createGlobalCtx() {
	// create global context
	int globalContextResult = hu_GlobalCtxCreateDefault(&this->globalCtx) ;
	// check the result of the creation
	switch(globalContextResult) {
		case SB_ERR_NULL_GLOBAL_CTX_PTR:
			qDebug("createGlobalCtx::Null Global context pointer") ;
			break;
		case SB_FAIL_ALLOC:
			qDebug("createGlobalCtx::Memory allocation failed") ;
			break;
		case SB_SUCCESS:
			qDebug("createGlobalCtx::Global context created successfully") ;
			break;
	}
}

void EncryptionService::registerDESContext() {
	// register global context
	int registerResult = hu_RegisterSbg56DES(this->globalCtx) ;
	// check the result of the registration
	if(registerResult != SB_SUCCESS) {
		qDebug("registerDESContext::Failed to register DES context. Encryption functions cannot be used.") ;
	}
}

void EncryptionService::initDESContext() {
	//  initialize global context
	int initResult = hu_InitSbg56(this->globalCtx) ;
	// check result of the initialization
	if(initResult != SB_SUCCESS) {
		qDebug("registerDESContext::Failed to initialize DES context. Encryption functions cannot be used.") ;
	}
}

void EncryptionService::createDESParams() {
	// configure DES algorithm behavior
	int paramCreateResult =  hu_DESParamsCreate(SB_DES_DES,
											    SB_DES_ECB,
											    SB_DES_PARITY_OFF,
											    SB_DES_WEAK_KEY_ON,
											    NULL,
											    NULL,
											    &(this->desParams),
											    globalCtx) ;
	// check the result of the paramter creation
	switch (paramCreateResult) {
		case SB_ERR_BAD_ALGORITHM:
			qDebug("createDESParams::Invalid algorithm") ;
			break;
		case SB_ERR_BAD_MODE:
			qDebug("createDESParams::Invalid mode of operation") ;
			break;
		case SB_ERR_NULL_PARAMS_PTR:
			qDebug("createDESParams::Null desParams") ;
			break;
		case SB_FAIL_ALLOC:
			qDebug("createDESParams::Memory allocation failed") ;
			break;
		case SB_SUCCESS:
			qDebug("createDESParams::Parameters created successfully") ;
			break;
		default:
			qDebug("createDESParams::Unknown result");
			break ;
	}
}

void EncryptionService::createDESKey() {
	// create DES key
	/**
	 * The algorithm used for the encryption is single DES encryption
	 *  key1 is the key for single DES encryption
	 * 	key2 is the key for double DES encryption set to NULL
	 * 	key3 is the key for triple DES encryption set to NULL
	 */
	int keyGenResult = hu_DESKeySet(desParams,
									// key 1
									SB_DES_KEY_SIZE,convertToUStr(encryptionKey),
									// key 2
									SB_DES_KEY_SIZE,NULL,
									// key 3
									SB_DES_KEY_SIZE,NULL,
									&this->desKey,
									globalCtx) ;
	// check the key creation result
	switch (keyGenResult) {
		case SB_ERR_NULL_PARAMS:
			qDebug("createDESKey::DES Param object is NULL") ;
			break;
		case SB_ERR_BAD_PARAMS:
			qDebug("createDESKey::DES Param object is invalid") ;
			break;
		case SB_ERR_NULL_KEY_PTR:
			qDebug("createDESKey::DES key object pointer is NULL") ;
			break;
		case SB_FAIL_ALLOC:
			qDebug("createDESKey::createDESKey::Memory allocation failure.") ;
			break;
		case SB_SUCCESS:
			qDebug("createDESKey::Key created successfully") ;
			break;
		default:
			break;
	}
}

void EncryptionService::createDESContext() {
	// creates context for DES encryption
	int contextCreateResult = hu_DESBegin(desParams,
										  desKey,
										  16,
										  iv,
										  &desContext,
										  globalCtx) ;

	// check the result of the context creation
	switch (contextCreateResult) {
		case SB_ERR_NULL_PARAMS:
			qDebug("createDESContext::DES Param object is NULL") ;
			break;
		case SB_ERR_BAD_PARAMS:
			qDebug("createDESContext::DES Param object is invalid") ;
			break;
		case SB_ERR_NULL_KEY:
			qDebug("createDESContext::DES Key object is NULL") ;
			break;
		case SB_ERR_BAD_KEY:
			qDebug("createDESContext::DES Key object is Invalid") ;
			break;
		case SB_ERR_NULL_IV:
			qDebug("createDESContext::IV is NULL") ;
			break;
		case SB_ERR_BAD_IV_LEN:
			qDebug("createDESContext::IV length is invalid") ;
			break;
		case SB_ERR_NULL_CONTEXT_PTR:
			qDebug("createDESContext::sbContext object is NULL") ;
			break;
		case SB_ERR_NO_MODE:
			qDebug("createDESContext::No Mode has been specified") ;
			break;
		case SB_FAIL_ALLOC:
			qDebug("createDESContext::Memory allocation failure.") ;
			break;
		case SB_SUCCESS:
			qDebug("createDESContext::DES Context created successfully") ;
			break;
	}
}

EncryptedItem EncryptionService::encryptData(QString plainText) {
	// convert plain text to unsigned char* for encryption
	unsigned char* input = convertToUStr(plainText);
	// find out the number of blocks to give length of the plain text
	/**
	 *	hu_DESEncrypt requires size of the plain text in multiple of SB_DES_BLOCK_SIZE
	 *	macro whose value is 8. After division, number blocks having complete 8 bit
	 *	is found.
	 */
	int numberOfBlocks = plainText.length() / SB_DES_BLOCK_SIZE ;
	/**
	 *  If plainText length is not divisible by 8 then extra block is added
	 */
	if(plainText.length() % SB_DES_BLOCK_SIZE != 0) {
		numberOfBlocks += 1 ;
	}
	/**
	 * multiply number of blocks by SB_DES_BLOCK_SIZE i.e. 8 to give the size of
	 * the plain text for encryption
	 */
	numberOfBlocks *= SB_DES_BLOCK_SIZE ;
	// allocate the memory of cipher text
	unsigned char* output = new unsigned char[numberOfBlocks] ;
	// encrypt given string
	int encResult = hu_DESEncrypt(desContext,
								  numberOfBlocks,
								  input,
								  output,
								  globalCtx) ;
	// check the result of the encryption
	switch (encResult) {
		case SB_ERR_NULL_CONTEXT:
			qDebug("encryptData::DES context object is NULL") ;
			break;
		case SB_ERR_BAD_CONTEXT:
			qDebug("encryptData::DES context object is invalid") ;
			break;
		case SB_ERR_NULL_INPUT_BUF:
			qDebug("encryptData::Plain text buffer is NULL") ;
			break;
		case SB_ERR_BAD_INPUT_BUF_LEN:
			qDebug("encryptData::Plain text buffer is invalid") ;
			break;
		case SB_ERR_NULL_OUTPUT_BUF:
			qDebug("encryptData::Cipher text buffer is NULL") ;
			break ;
		case SB_SUCCESS:
			qDebug("encryptData::Encrypted successfully") ;
			break;
	}
	qDebug() << "Encrypted text : " << output << " :: Size : " << numberOfBlocks ;
	// return encrypted item containing cipher text and number of blocks
	return EncryptedItem(output,numberOfBlocks) ;
}

QString EncryptionService::decryptData(EncryptedItem encryptedItem) {
	// allocate the memory of decrypted text
	unsigned char* output = new unsigned char[encryptedItem.getDESBlockSize()] ;
	// decrypt encrypted text in encrypted item
	int decResult = hu_DESDecrypt(desContext,
								  encryptedItem.getDESBlockSize(),
								  encryptedItem.getCipherText(),
								  output,
								  globalCtx) ;
	// check decryption result
	switch (decResult) {
		case SB_ERR_NULL_CONTEXT:
			qDebug("decryptData::DES context object is NULL") ;
			break;
		case SB_ERR_BAD_CONTEXT:
			qDebug("decryptData::DES context object is invalid") ;
			break;
		case SB_ERR_NULL_INPUT_BUF:
			qDebug("decryptData::Cipher text buffer is NULL") ;
			break;
		case SB_ERR_BAD_INPUT_BUF_LEN:
			qDebug("decryptData::Cipher text buffer is invalid") ;
			break;
		case SB_ERR_NULL_OUTPUT_BUF:
			qDebug("decryptData::Plain text buffer is NULL") ;
			break ;
		case SB_SUCCESS:
			qDebug("decryptData::Decrypted successfully") ;
			break;
	}
	int i=0 ;
	// convert unsigned char* output to char*
	char* decryptedText = new char[encryptedItem.getDESBlockSize()+1] ;
	for( ; i<encryptedItem.getDESBlockSize() ; i++) {
		decryptedText[i] = (char)output[i] ;
	}
	decryptedText[i] = '\0' ;
	delete output ;
	// return decrypted string
	return QString(decryptedText) ;
}

EncryptionService::~EncryptionService() {
	// nothing to do
}

unsigned char* EncryptionService::convertToUStr(QString qsConvertString){
	string convetString = qsConvertString.toStdString() ;
	unsigned char* bytes = new unsigned char[convetString.size()+1]();
	std::copy(convetString.begin(),convetString.end(),bytes);
	return(bytes);
}

int EncryptionService::ustrlen(unsigned char* str) {
	int length = 0 ;
	while((char)str[length] != '\0') {
		length++ ;
	}
	return length ;
}
