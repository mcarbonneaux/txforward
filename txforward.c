/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2008 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Francois Cartegnie <pecldev@free.fr>                         |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_txforward.h"


ZEND_DECLARE_MODULE_GLOBALS(txforward)

/* {{{ txforward_module_entry
 */
zend_module_entry txforward_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    TXFORWARDING_EXTNAME,
    NULL,
    PHP_MINIT(txforward),
    PHP_MSHUTDOWN(txforward),
    PHP_RINIT(txforward),
    NULL,
    PHP_MINFO(txforward),
#if ZEND_MODULE_API_NO >= 20010901
    TXFORWARDING_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_TXFORWARD
ZEND_GET_MODULE(txforward)
#endif

/* Declare PHP ini configuration entry */
PHP_INI_BEGIN()
	STD_PHP_INI_ENTRY("txforward.depth", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateLong, proxy_depth, zend_txforward_globals, txforward_globals)
PHP_INI_END()

static void php_txforward_init_globals(zend_txforward_globals *txforward_globals)
{
	txforward_globals->proxy_depth = 1;
}

/*
 * Returns the number Nth position from end of c in the string s
 */
char * php_strrchr_n(char * s, int c, int * number)
{
       char * localperiodpointer = NULL;
       char * nextperiodpointer = NULL;
       localperiodpointer = strchr(s, c);
       if (localperiodpointer!=NULL)
       {
            nextperiodpointer = php_strrchr_n(localperiodpointer + 1, c, number);
            *number = *number - 1; /* Give my position from the end */
       }       
       
       if (*number == 0) /* My position is now zero, that what we're looking for */
           return localperiodpointer;
       else       
           return nextperiodpointer; /* Has been/not been found yet */
}


PHP_MINFO_FUNCTION(txforward)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "Transparent X-Forwarding Support", "enabled");
	php_info_print_table_row(2, "Version", TXFORWARDING_VERSION);
	php_info_print_table_row(2, "Security", TXFORWARDING_WARNING);
	php_info_print_table_row(2, "Real IP stored in", "$_SERVER['REAL_REMOTE_ADDR']");	
	php_info_print_table_end();
	DISPLAY_INI_ENTRIES();
}

PHP_MINIT_FUNCTION(txforward)
{	
	ZEND_INIT_MODULE_GLOBALS(txforward, php_txforward_init_globals, NULL);
	REGISTER_INI_ENTRIES();
	if (TXFORWARD_G(proxy_depth)<1)	TXFORWARD_G(proxy_depth) = 1; /* sanitize */
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(txforward)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}

PHP_RINIT_FUNCTION(txforward)
{
	zval **serverhash = NULL;
	zval **remote_addr = NULL;
	zval *real_remote_addr = NULL;
	zval **forwarded_for = NULL;
	zval **pass = NULL;
	zval *newval = NULL;
	HashTable *htable;	
	char *periodpointer = NULL;
	char *tailpointer = NULL;
	char *startpointer = NULL;
	char *newstring = NULL;
	int oldstringsize=0;
	int currentdepth=1;
	char *oldpointer = NULL;
	
#ifdef ZEND_ENGINE_2_1
	zend_is_auto_global("_SERVER", sizeof("_SERVER") - 1 TSRMLS_CC);
#endif
	if (zend_hash_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER"), (void **) &serverhash) != SUCCESS || Z_TYPE_PP(serverhash) != IS_ARRAY) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "_SERVER is corrupted");
		zend_bailout();
	}
	htable = HASH_OF((*serverhash));

	if (zend_hash_find(htable, "HTTP_X_FORWARDED_FOR", sizeof("HTTP_X_FORWARDED_FOR"), (void **) &forwarded_for) == FAILURE) {
	 	forwarded_for = NULL;
	} else 
	if (zend_hash_find(htable, "REMOTE_ADDR", sizeof("REMOTE_ADDR"), (void **) &remote_addr) == FAILURE) {
		remote_addr = NULL;
	} else 
	if (Z_TYPE_PP(forwarded_for) != IS_STRING || Z_TYPE_PP(remote_addr) != IS_STRING) {
		forwarded_for = NULL;
		remote_addr = NULL;
	} else {
		/* The remote address itself is behind a proxy. X-Forwarded:IP1, IP2, IP3.. only keep the trusted one*/
		/* create a new PHP variable. */
		MAKE_STD_ZVAL(real_remote_addr);
		*real_remote_addr = **remote_addr; /* copy content */
		zval_copy_ctor(real_remote_addr);
		zend_hash_add(htable, "REAL_REMOTE_ADDR", sizeof("REAL_REMOTE_ADDR"), &real_remote_addr, sizeof(zval*), NULL);

		oldstringsize = (**forwarded_for).value.str.len;
		oldpointer = (**forwarded_for).value.str.val;		

		if (TXFORWARD_G(proxy_depth) > 1)
		{
			currentdepth = TXFORWARD_G(proxy_depth); /* not sure if I can modify ini's one without doing it globally */
			periodpointer = php_strrchr_n((**forwarded_for).value.str.val, ',', &currentdepth); /* Find end of IP.*/
		} else {
			periodpointer = strrchr((**forwarded_for).value.str.val, ',');
		}
		
		if ( (periodpointer == NULL) || (periodpointer == (**forwarded_for).value.str.val) )
			tailpointer = (**forwarded_for).value.str.val + (**forwarded_for).value.str.len; /* didn't found any period in our header */
		else	tailpointer = periodpointer - 1;
		
		periodpointer=tailpointer;
		while ( (periodpointer > (**forwarded_for).value.str.val) && (*periodpointer != ',') ) periodpointer--;

		if ( ((periodpointer + 2) > tailpointer) || (periodpointer == (**forwarded_for).value.str.val) )
			startpointer = (**forwarded_for).value.str.val;
		else	
			startpointer = periodpointer + 2; /* period + space */
		
		/* let's fake string length, so only our wanted bytes will be copied and allocated by zval_copy_ctor in our new zend variable */
		(**forwarded_for).value.str.len = tailpointer - startpointer +1 ; /* fake length */
		(**forwarded_for).value.str.val = startpointer;
				
		MAKE_STD_ZVAL(newval);
		*newval = **forwarded_for;

		zval_copy_ctor(*forwarded_for); /*more efficient copy*/

		(**forwarded_for).value.str.len = oldstringsize; /* restore length in case we changed it before copy */
		(**forwarded_for).value.str.val = oldpointer; /* restore original string pointer */
		
		zend_hash_del(htable, "REMOTE_ADDR", sizeof("REMOTE_ADDR"));

		zend_hash_update(htable, "REMOTE_ADDR", sizeof("REMOTE_ADDR"), &newval, sizeof(zval*), NULL);

	}

	return SUCCESS;
}



/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
