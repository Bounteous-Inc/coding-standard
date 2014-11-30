<?php
/**
 * @author Allan MacGregor - Magento Practice Lead <amacgregor@demacmedia.com>
 * @company Demac Media Inc.
 * @copyright 2010-2014 Demac Media Inc.
 */

class Ecg_Sniffs_Classes_Magento_Template_GodClassSniff extends Generic_Sniffs_PHP_ForbiddenFunctionsSniff
{
    protected $patternMatch = true;

    protected $forbiddenFunctions = array(
        'app.*$'  => null,
        'getModel.*$'  => null,
        'getResourceModel.*$' => null,
        'register.*$' => null,
        'unregister.*$' => null,
        'registry.*$' => null,
        'getModuleDir.*$' => null,
        'getStoreConfig.*$' => null,
        'getStoreConfigFlag.*$' => null,
        'dispatchEvent.*$' => null,
        'getConfig.*$' => null,
        'getSingleton.*$' => null,
        'getControllerInstance.*$' => null,
        'getResourceSingleton.*$' => null,
        'getBlockSingleton.*$' => null,
        'getResourceHelper.*$' => null,
        'log.*$' => null,
        'getConfig.*$' => null,
        'getConfig.*$' => null,
        'getConfig.*$' => null,
        '^assert$' => null,
        '^bind_textdomain_codeset$' => null,
        '^bindtextdomain$' => null,
        '^bz.*$' => null,
        '^call_user_func$' => null,
        '^call_user_func_array$' => null,
        '^chdir$' => null,
        '^chgrp$' => null,
        '^chmod$' => null,
        '^chown$' => null,
        '^chroot$' => null,
        '^com_load_typelib$' => null,
        '^constant$' => null,
        '^copy$' => null,
        '^create_function$' => null,
        '^curl_.*$' => null,
        '^cyrus_connect$' => null,
        '^dba_.*$' => null,
        '^dbase_.*$' => null,
        '^dbx_.*$' => null,
        '^dcgettext$' => null,
        '^dcngettext$' => null,
        '^dgettext$' => null,
        '^dio_.*$' => null,
        '^dirname$' => null,
        '^dngettext$' => null,
        '^domxml_.*$' => null,
        '^exec$' => null,
        '^fbsql_.*$' => null,
        '^fdf_add_doc_javascript$' => null,
        '^fdf_open$' => null,
        '^fopen$' => null,
        '^fsockopen$' => null,
        '^ftp_.*$' => null,
        '^fwrite$' => null,
        '^gettext$' => null,
        '^gz.*$' => null,
        '^header$' => null,
        '^highlight_file$' => null,
        '^ibase_.*$' => null,
        '^iconv_set_encoding$' => null,
        '^id3_set_tag$' => null,
        '^ifx_.*$' => null,
        '^image.*$' => null,
        '^imap_.*$' => null,
        '^ingres_.*$' => null,
        '^ircg_.*$' => null,
        '^ldap_.*$' => null,
        '^link$' => null,
        '^mail$' => null,
        '^mb_send_mail$' => null,
        '^mkdir$' => null,
        '^move_uploaded_file$' => null,
        '^msession_.*$' => null,
        '^msg_send$' => null,
        '^msql$' => null,
        '^msql_.*$' => null,
        '^mssql_.*$' => null,
        '^mysql_.*$' => null,
        '^odbc_.*$' => null,
        '^opendir$' => null,
        '^openlog$' => null,
        '^ora_.*$' => null,
        '^ovrimos_.*$' => null,
        '^parse_ini_file$' => null,
        '^parse_str$' => null,
        '^parse_url$' => null,
        '^parsekit_compile_string$' => null,
        '^passthru$' => null,
        '^pcntl_.*$' => null,
        '^posix_.*$' => null,
        '^pfpro_.*$' => null,
        '^pfsockopen$' => null,
        '^pg_.*$' => null,
        '^php_check_syntax$' => null,
        '^popen$' => null,
        '^print_r$' => null,
        '^printf$' => null,
        '^proc_open$' => null,
        '^putenv$' => null,
        '^readfile$' => null,
        '^readgzfile$' => null,
        '^readline$' => null,
        '^readlink$' => null,
        '^register_shutdown_function$' => null,
        '^register_tick_function$' => null,
        '^rename$' => null,
        '^rmdir$' => null,
        '^scandir$' => null,
        '^session_.*$' => null,
        '^set_include_path$' => null,
        '^set_ini$' => null,
        '^set_time_limit$' => null,
        '^setcookie$' => null,
        '^setlocale$' => null,
        '^setrawcookie$' => null,
        '^shell_exec$' => null,
        '^sleep$' => null,
        '^socket_.*$' => null,
        '^stream_.*$' => null,
        '^sybase_.*$' => null,
        '^symlink$' => null,
        '^syslog$' => null,
        '^system$' => null,
        '^touch$' => null,
        '^trigger_error$' => null,
        '^unlink$' => null,
        '^vprintf$' => null,
        '^mysqli.*$' => null,
        '^oci_connect$' => null,
        '^oci_pconnect$' => null,
        '^quotemeta$' => null,
        '^sqlite_popen$' => null,
        '^time_nanosleep$' => null,
        '^base64_decode$' => null,
        '^base_convert$' => null,
        '^basename$' => null,
        '^chr$' => null,
        '^convert_cyr_string$' => null,
        '^dba_nextkey$' => null,
        '^dns_get_record$' => null,
        '^extract$' => null,
        '^fdf_.*$' => null,
        '^fget.*$' => null,
        '^fread$' => null,
        '^fflush$' => null,
        '^get_browser$' => null,
        '^get_headers$' => null,
        '^get_meta_tags$' => null,
        '^getallheaders$' => null,
        '^getenv$' => null,
        '^getopt$' => null,
        '^headers_list$' => null,
        '^hebrev$' => null,
        '^hebrevc$' => null,
        '^highlight_string$' => null,
        '^html_entity_decode$' => null,
        '^ibase_blob_import$' => null,
        '^iconv$' => null,
        '^id3_get_tag$' => null,
        '^import_request_variables$' => null,
        '^ircg_nickname_unescape$' => null,
        '^ldap_get_values$' => null,
        '^mb_decode_mimeheader$' => null,
        '^mb_parse_str$' => null,
        '^mcrypt_decrypt$' => null,
        '^mdecrypt_generic$' => null,
        '^msg_receive$' => null,
        '^ngettext$' => null,
        '^ob_get_contents$' => null,
        '^ob_get_flush$' => null,
        '^rawurldecode$' => null,
        '^shm_get_var$' => null,
        '^stripcslashes$' => null,
        '^stripslashes$' => null,
        '^strval$' => null,
        '^token_get_all$' => null,
        '^unpack$' => null,
        '^convert_uudecode$' => null,
        '^iconv_mime_decode$' => null,
        '^iconv_mime_decode_headers$' => null,
        '^php_strip_whitespace$' => null,
        '^addcslashes$' => null,
        '^addslashes$' => null,
        '^escapeshellarg$' => null,
        '^escapeshellcmd$' => null,
        '^gettype$' => null,
        '^var_dump$' => null,
        '^tempnam$' => null,
        '^realpath$' => null,
        '^pathinfo$' => null,
        '^linkinfo$' => null,
        '^lstat$' => null,
        '^stat$' => null,
        '^lchgrp$' => null,
        '^lchown$' => null,
        '^show_source$' => null,
        '^is_dir$' => null,
        '^is_executable$' => null,
        '^is_file$' => null,
        '^is_link$' => null,
        '^is_readable$' => null,
        '^is_writable$' => null,
        '^is_writeable$' => null,
        '^is_uploaded_file$' => null,
        '^glob$' => null,
        '^ssh2_.*$' => null,
        '^delete$' => null,
        '^file.*$' => null,
    );



    /**
     * Processes this test, when one of its tokens is encountered.
     *
     * @param PHP_CodeSniffer_File $phpcsFile The file being scanned.
     * @param int                  $stackPtr  The position of the current token in
     *                                        the stack passed in $tokens.
     *
     * @return void
     */
    public function process(PHP_CodeSniffer_File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();

        $ignore = array(
            T_OBJECT_OPERATOR,
            T_FUNCTION,
            T_CONST,
            T_PUBLIC,
            T_PRIVATE,
            T_PROTECTED,
            T_AS,
            T_NEW,
            T_INSTEADOF,
            T_NS_SEPARATOR,
            T_IMPLEMENTS,
        );

        if(strtolower(substr($phpcsFile->getFilename(), -6)) == '.phtml')
        {

            $prevToken = $phpcsFile->findPrevious(T_WHITESPACE, ($stackPtr - 1), null, true);

            // If function call is directly preceded by a NS_SEPARATOR it points to the
            // global namespace, so we should still catch it.
            if ($tokens[$prevToken]['code'] === T_NS_SEPARATOR) {
                $prevToken = $phpcsFile->findPrevious(T_WHITESPACE, ($prevToken - 1), null, true);
                if ($tokens[$prevToken]['code'] === T_STRING) {
                    // Not in the global namespace.
                    return;
                }
            }

            if (in_array($tokens[$prevToken]['code'], $ignore) === true) {
                // Not a call to a PHP function.
                return;
            }

            $nextToken = $phpcsFile->findNext(T_WHITESPACE, ($stackPtr + 1), null, true);
            if (in_array($tokens[$nextToken]['code'], $ignore) === true) {
                // Not a call to a PHP function.
                return;
            }

            $function = strtolower($tokens[$stackPtr]['content']);
            $pattern  = null;

            if ($this->patternMatch === true) {
                $count   = 0;
                $pattern = preg_replace(
                    $this->forbiddenFunctionNames,
                    $this->forbiddenFunctionNames,
                    $function,
                    1,
                    $count
                );

                if ($count === 0) {
                    return;
                }

                // Remove the pattern delimiters and modifier.
                $pattern = substr($pattern, 1, -2);
            } else {
                if (in_array($function, $this->forbiddenFunctionNames) === false) {
                    return;
                }
            }

            $this->addError($phpcsFile, $stackPtr, $function, $pattern);
        }

    }//end process()

}
