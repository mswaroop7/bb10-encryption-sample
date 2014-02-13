/*
 * Hash.h
 *
 *  Created on: Oct 23, 2013
 *      Author: swaroop.mahajan
 */

#ifndef HASH_H_
#define HASH_H_

#include <husha1.h>
#include <sbreturn.h>
#include <huctx.h>

class Hash {

private :
	sb_GlobalCtx globalCtx ;

public:
	Hash();
	virtual ~Hash();
};

#endif /* HASH_H_ */
