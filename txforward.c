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

/* If you declare any globals in php_txforward.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(txforward)
*/

/* True global resources - no need for thread safety here */
static int le_txforward;

/* {{{ txforward_functions[]
 *
 * Every user visible function must have an entry in txforward_functions[].
 */
zend_function_entry txforward_functions[] = {
	{NULL, NULL, NULL}	/* Must be the last line in txforward_functions[] */
};
/* }}} */

/* {{{ txforward_module_entry
 */
zend_module_entry txforward_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    TXFORWARDING_EXTNAME,
    NULL,
    NULL,
    NULL,
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

PHP_MINFO_FUNCTION(txforward)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "Transparent X-Forwarding Support", "enabled");
	php_info_print_table_row(2, "Version", TXFORWARDING_VERSION);
	php_info_print_table_row(2, "Security", TXFORWARDING_WARNING);
	php_info_print_table_row(2, "Real IP stored in", "$_SERVER['REAL_REMOTE_ADDR']");	
	php_info_print_table_end();
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
	char *newstring = NULL;
	int oldstringsize=0;
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
		/* create a new PHP variable. */
		MAKE_STD_ZVAL(real_remote_addr);
		*real_remote_addr = **remote_addr; /* copy content */
		zval_copy_ctor(real_remote_addr);
		zend_hash_add(htable, "REAL_REMOTE_ADDR", sizeof("REAL_REMOTE_ADDR"), &real_remote_addr, sizeof(zval*), NULL);


		periodpointer = strrchr((**forwarded_for).value.str.val, ',');
		oldstringsize = (**forwarded_for).value.str.len;
		oldpointer = (**forwarded_for).value.str.val;
		
		if ( periodpointer != NULL )
		{ /* The remote address itself is behind a proxy. X-Forwarded:IP1, IP2, IP3.. keep only the trusted one*/
			/* let's fake string length, so only our wanted bytes will be copied and allocated by zval_copy_ctor in our new zend variable */
			periodpointer = periodpointer + 1;  /* space after period */
			(**forwarded_for).value.str.len = ((**forwarded_for).value.str.val + (**forwarded_for).value.str.len) - periodpointer - 1; /* fake length */
			(**forwarded_for).value.str.val = periodpointer + 1;
		}
				
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
