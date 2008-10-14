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

#ifndef PHP_TXFORWARD_H
#define PHP_TXFORWARD_H

extern zend_module_entry txforward_module_entry;
#define phpext_txforward_ptr &txforward_module_entry

#ifdef PHP_WIN32
#define PHP_TXFORWARD_API __declspec(dllexport)
#else
#define PHP_TXFORWARD_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_RINIT_FUNCTION(txforward);
PHP_MINFO_FUNCTION(txforward);

#define TXFORWARDING_NAME       "Transparent X-Forwarding"
#define TXFORWARDING_EXTNAME    "txforward"
#define TXFORWARDING_VERSION    "1.03"
#define TXFORWARDING_WARNING    "This module must only be used with trusted reverse proxies, and without proxy chain propagation."

#ifdef ZTS
#define TXFORWARD_G(v) TSRMG(txforward_globals_id, zend_txforward_globals *, v)
#else
#define TXFORWARD_G(v) (txforward_globals.v)
#endif

#endif	/* PHP_TXFORWARD_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
