import os
import shutil
import re
import hashlib
import stat
import time

QUARANTINE_DIR = None

def init_quarantine_dir(settings):
    global QUARANTINE_DIR
    QUARANTINE_DIR = settings.get("quarantine_dir", "quarantine")
    secure_quarantine_dir(QUARANTINE_DIR)



DANGEROUS_FUNCTIONS = [
    r"eval\s*\(",
    r"assert\s*\(",
    r"create_function\s*\(",
    r"forward_static_call\s*\(",
    r"forward_static_call_array\s*\(",
    r"register_tick_function\s*\(",
    r"unregister_tick_function\s*\(",
    
    r"system\s*\(",
    r"exec\s*\(",
    r"shell_exec\s*\(",
    r"passthru\s*\(",
    r"proc_open\s*\(",
    r"popen\s*\(",
    r"pcntl_exec\s*\(",
    
    r"pcntl_fork\s*\(",
    r"pcntl_signal\s*\(",
    r"pcntl_alarm\s*\(",
    r"pcntl_async_signals\s*\(",
    
    r"include\s*\(",
    r"include_once\s*\(",
    r"require\s*\(",
    r"require_once\s*\(",
    
    r"file_put_contents\s*\(",
    r"fwrite\s*\(",
    r"fputs\s*\(",
    r"fprintf\s*\(",
    r"ftruncate\s*\(",
    
    r"file_get_contents\s*\(",
    r"fread\s*\(",
    r"fgets\s*\(",
    r"fgetc\s*\(",
    r"fgetss\s*\(",
    r"fscanf\s*\(",
    r"readfile\s*\(",
    r"readlink\s*\(",
    
    r"copy\s*\(",
    r"rename\s*\(",
    r"move_uploaded_file\s*\(",
    r"unlink\s*\(",
    r"rmdir\s*\(",
    r"mkdir\s*\(",
    r"chmod\s*\(",
    r"chown\s*\(",
    r"chgrp\s*\(",
    r"touch\s*\(",
    r"symlink\s*\(",
    r"link\s*\(",
    
    r"fsockopen\s*\(",
    r"pfsockopen\s*\(",
    r"stream_socket_client\s*\(",
    r"stream_socket_server\s*\(",
    r"socket_create\s*\(",
    r"socket_connect\s*\(",
    r"socket_bind\s*\(",
    r"socket_listen\s*\(",
    r"socket_accept\s*\(",
    
    r"curl_exec\s*\(",
    r"curl_multi_exec\s*\(",
    r"fopen\s*\(.*http[s]?://",
    r"file_get_contents\s*\(.*http[s]?://",
    
    r"gethostbyname\s*\(",
    r"gethostbyaddr\s*\(",
    r"getmxrr\s*\(",
    r"checkdnsrr\s*\(",
    r"dns_get_record\s*\(",
    
    r"base64_decode\s*\(",
    r"base64_encode\s*\(",
    r"gzinflate\s*\(",
    r"gzuncompress\s*\(",
    r"gzdecode\s*\(",
    r"gzinflate\s*\(",
    r"str_rot13\s*\(",
    r"convert_uuencode\s*\(",
    r"convert_uudecode\s*\(",
    r"hex2bin\s*\(",
    r"bin2hex\s*\(",
    r"pack\s*\(",
    r"unpack\s*\(",
    
    r"gzcompress\s*\(",
    r"gzdeflate\s*\(",
    r"bzcompress\s*\(",
    r"lzf_compress\s*\(",
    r"lzf_decompress\s*\(",
    
    r"preg_replace\s*\(.*/e",
    r"preg_filter\s*\(.*/e",
    
    r"unserialize\s*\(",
    r"serialize\s*\(",
    r"igbinary_unserialize\s*\(",
    r"igbinary_serialize\s*\(",
    r"msgpack_unpack\s*\(",
    r"msgpack_pack\s*\(",
    
    r"get_defined_functions\s*\(",
    r"get_defined_vars\s*\(",
    r"get_defined_constants\s*\(",
    r"get_declared_classes\s*\(",
    r"get_declared_interfaces\s*\(",
    r"get_declared_traits\s*\(",
    
    r"get_class_methods\s*\(",
    r"get_class_vars\s*\(",
    r"get_object_vars\s*\(",
    
    r"call_user_func\s*\(",
    r"call_user_func_array\s*\(",
    r"call_user_method\s*\(",
    r"call_user_method_array\s*\(",
    
    r"variable_\s*\(",
    r"extract\s*\(",
    r"compact\s*\(",
    r"parse_str\s*\(",
    r"get_defined_vars\s*\(",
    
    r"assert\s*\(",
    r"assert_options\s*\(",
    
    r"stream_wrapper_register\s*\(",
    r"stream_register_wrapper\s*\(",
    r"stream_wrapper_unregister\s*\(",
    
    r"php://input",
    r"php://filter",
    r"php://memory",
    r"php://temp",
    r"data://",
    r"expect://",
    r"phar://",
    
    r"mysql_query\s*\(",
    r"mysqli_query\s*\(",
    r"pg_query\s*\(",
    r"sqlite_query\s*\(",
    r"oci_parse\s*\(",
    r"oci_execute\s*\(",
    
    r"sqlite_exec\s*\(",
    r"sqlite_array_query\s*\(",
    r"sqlite_single_query\s*\(",
    r"sqlite_unbuffered_query\s*\(",
    
    r"ldap_search\s*\(",
    r"ldap_read\s*\(",
    r"ldap_list\s*\(",
    r"ldap_get_entries\s*\(",
    r"ldap_first_entry\s*\(",
    r"ldap_next_entry\s*\(",
    
    r"simplexml_load_file\s*\(",
    r"simplexml_load_string\s*\(",
    r"DOMDocument::loadXML\s*\(",
    r"DOMDocument::loadHTML\s*\(",
    r"SimpleXMLElement::__construct\s*\(",
    
    r"xml_parse\s*\(",
    r"xml_parser_create\s*\(",
    r"xml_parser_create_ns\s*\(",
    
    r"mail\s*\(",
    r"mb_send_mail\s*\(",
    r"imap_open\s*\(",
    r"imap_mail\s*\(",
    
    r"session_start\s*\(",
    r"session_id\s*\(",
    r"session_regenerate_id\s*\(",
    r"session_decode\s*\(",
    r"session_encode\s*\(",
    
    r"header\s*\(",
    r"headers_sent\s*\(",
    r"headers_list\s*\(",
    r"setcookie\s*\(",
    r"setrawcookie\s*\(",
    
    r"ob_start\s*\(",
    r"ob_get_contents\s*\(",
    r"ob_end_clean\s*\(",
    r"ob_end_flush\s*\(",
    r"ob_clean\s*\(",
    r"ob_flush\s*\(",
    
    r"error_reporting\s*\(",
    r"set_error_handler\s*\(",
    r"restore_error_handler\s*\(",
    r"set_exception_handler\s*\(",
    r"restore_exception_handler\s*\(",
    r"trigger_error\s*\(",
    r"user_error\s*\(",
    
    r"phpinfo\s*\(",
    r"getenv\s*\(",
    r"putenv\s*\(",
    r"get_cfg_var\s*\(",
    r"ini_get\s*\(",
    r"ini_set\s*\(",
    r"ini_restore\s*\(",
    r"ini_get_all\s*\(",
    
    r"get_current_user\s*\(",
    r"getmyuid\s*\(",
    r"getmygid\s*\(",
    r"getmypid\s*\(",
    r"getmyinode\s*\(",
    r"getlastmod\s*\(",
    
    r"scandir\s*\(",
    r"glob\s*\(",
    r"readdir\s*\(",
    r"opendir\s*\(",
    r"dir\s*\(",
    
    r"posix_kill\s*\(",
    r"posix_getpwuid\s*\(",
    r"posix_getgrgid\s*\(",
    r"posix_geteuid\s*\(",
    r"posix_getegid\s*\(",
    
    r"wget\s",
    r"curl\s",
    r"lynx\s",
    r"links\s",
    r"ftp\s",
    r"telnet\s",
    r"nc\s",
    r"ncat\s",
    r"netcat\s",
    r"ssh\s",
    r"scp\s",
    r"sftp\s",
    r"rsync\s",
    
    r"zip_open\s*\(",
    r"zip_read\s*\(",
    r"zip_entry_open\s*\(",
    r"zip_entry_read\s*\(",
    
    r"rar_open\s*\(",
    r"rar_list\s*\(",
    r"rar_extract\s*\(",
    
    r"openssl_public_encrypt\s*\(",
    r"openssl_private_decrypt\s*\(",
    r"openssl_sign\s*\(",
    r"openssl_verify\s*\(",
    r"openssl_seal\s*\(",
    r"openssl_open\s*\(",
    
    r"mcrypt_encrypt\s*\(",
    r"mcrypt_decrypt\s*\(",
    r"mcrypt_ofb\s*\(",
    r"mcrypt_cfb\s*\(",
    r"mcrypt_cbc\s*\(",
    
    r"imagecreatefromjpeg\s*\(",
    r"imagecreatefrompng\s*\(",
    r"imagecreatefromgif\s*\(",
    r"imagecreatefromwbmp\s*\(",
    r"imagecreatefromwebp\s*\(",
    
    r"imagejpeg\s*\(",
    r"imagepng\s*\(",
    r"imagegif\s*\(",
    r"imagewbmp\s*\(",
    r"imagewebp\s*\(",
    
    r"str_replace\s*\(.*\$_",
    r"preg_replace\s*\(.*\$_",
    r"str_ireplace\s*\(.*\$_",
    
    r"dl\s*\(",
    r"enable_dl\s*\(",
    r"extension_loaded\s*\(",
    r"get_loaded_extensions\s*\(",
    r"get_extension_funcs\s*\(",
    
    r"__halt_compiler\s*\(",
    r"__autoload\s*\(",
    r"spl_autoload_register\s*\(",
    r"spl_autoload_unregister\s*\(",
    
    r"sleep\s*\(",
    r"usleep\s*\(",
    r"time_nanosleep\s*\(",
    r"time_sleep_until\s*\(",
    
    r"shmop_open\s*\(",
    r"shmop_read\s*\(",
    r"shmop_write\s*\(",
    r"shmop_delete\s*\(",
    
    r"shm_attach\s*\(",
    r"shm_get_var\s*\(",
    r"shm_put_var\s*\(",
    r"shm_remove_var\s*\(",
    
    r"sem_get\s*\(",
    r"sem_acquire\s*\(",
    r"sem_release\s*\(",
    r"sem_remove\s*\(",
    
    r"msg_get_queue\s*\(",
    r"msg_send\s*\(",
    r"msg_receive\s*\(",
    r"msg_remove_queue\s*\(",
    
    r"ftp_connect\s*\(",
    r"ftp_login\s*\(",
    r"ftp_put\s*\(",
    r"ftp_get\s*\(",
    r"ftp_nb_put\s*\(",
    r"ftp_nb_get\s*\(",
    
    r"SoapClient::__construct\s*\(",
    r"SoapServer::__construct\s*\(",
    
    r"http_build_query\s*\(",
    r"parse_url\s*\(",
    r"urlencode\s*\(",
    r"urldecode\s*\(",
    r"rawurlencode\s*\(",
    r"rawurldecode\s*\(",
    
    r"js_decode\s*\(",
    r"js_encode\s*\(",
    
    r"ob_get_clean\s*\(",
    r"ob_get_flush\s*\(",
    r"ob_get_length\s*\(",
    r"ob_get_level\s*\(",
    r"ob_get_status\s*\(",
    
    r"zend_version\s*\(",
    r"get_include_path\s*\(",
    r"set_include_path\s*\(",
    r"restore_include_path\s*\(",
    
    r"com_load\s*\(",
    r"dotnet_load\s*\(",
    r"variant_set\s*\(",
    r"variant_get\s*\(",
    
    r"w32api_invoke_function\s*\(",
    r"w32api_register_function\s*\(",
    r"w32api_set_call_method\s*\(",
    
    r"debug_backtrace\s*\(",
    r"debug_print_backtrace\s*\(",
    r"error_get_last\s*\(",
    r"error_log\s*\(",
    
    r"hash\s*\(",
    r"hash_file\s*\(",
    r"hash_hmac\s*\(",
    r"hash_hmac_file\s*\(",
    r"md5\s*\(",
    r"md5_file\s*\(",
    r"sha1\s*\(",
    r"sha1_file\s*\(",
    r"crc32\s*\(",
    
    r"PDF_begin_document\s*\(",
    r"PDF_end_document\s*\(",
    r"PDF_open_file\s*\(",
    r"PDF_close\s*\(",
    
    r"swf_actiongeturl\s*\(",
    r"swf_actiongotolabel\s*\(",
    r"swf_actiongotoframe\s*\(",
    r"swf_actionnextframe\s*\(",
    r"swf_actionplay\s*\(",
    r"swf_actionprevframe\s*\(",
    r"swf_actionsettarget\s*\(",
    r"swf_actionstop\s*\(",
    r"swf_actiontogglequality\s*\(",
    r"swf_actionwaitforframe\s*\(",
    
    r"ReflectionFunction::__construct\s*\(",
    r"ReflectionMethod::__construct\s*\(",
    r"ReflectionClass::__construct\s*\(",
    r"ReflectionProperty::__construct\s*\(",
    r"ReflectionParameter::__construct\s*\(",
    
    r"PDO::__construct\s*\(",
    r"PDO::exec\s*\(",
    r"PDO::query\s*\(",
    r"PDO::prepare\s*\(",
    r"PDOStatement::execute\s*\(",
    
    r"ignore_user_abort\s*\(",
    r"connection_aborted\s*\(",
    r"connection_status\s*\(",
    
    r"flush\s*\(",
    r"ob_implicit_flush\s*\(",
    
    r"register_shutdown_function\s*\(",
    
    r"fpassthru\s*\(",
    r"readgzfile\s*\(",
    r"gzfile\s*\(",
    r"gzpassthru\s*\(",
    
    r"str_contains\s*\(.*\$_",
    r"str_starts_with\s*\(.*\$_",
    r"str_ends_with\s*\(.*\$_",
    
    r"array_map\s*\(.*\$_",
    r"array_filter\s*\(.*\$_",
    r"array_reduce\s*\(.*\$_",
    r"array_walk\s*\(.*\$_",
    r"array_walk_recursive\s*\(.*\$_",
    
    r"iterator_apply\s*\(",
    r"iterator_to_array\s*\(",
    
    r"stream_filter_append\s*\(",
    r"stream_filter_prepend\s*\(",
    r"stream_filter_remove\s*\(",
    
    r"stream_context_create\s*\(",
    r"stream_context_set_option\s*\(",
    r"stream_context_set_params\s*\(",
    r"stream_context_get_options\s*\(",
    r"stream_context_get_params\s*\(",
    
    r"socket_get_option\s*\(",
    r"socket_set_option\s*\(",
    r"socket_getpeername\s*\(",
    r"socket_getsockname\s*\(",
    r"socket_set_block\s*\(",
    r"socket_set_nonblock\s*\(",
    r"socket_shutdown\s*\(",
    r"socket_close\s*\(",
    
    r"curl_setopt\s*\(",
    r"curl_setopt_array\s*\(",
    r"curl_getinfo\s*\(",
    r"curl_error\s*\(",
    r"curl_errno\s*\(",
    r"curl_close\s*\(",
    r"curl_multi_setopt\s*\(",
    r"curl_multi_getcontent\s*\(",
    
    r"ftp_raw\s*\(",
    r"ftp_rawlist\s*\(",
    r"ftp_site\s*\(",
    r"ftp_size\s*\(",
    r"ftp_alloc\s*\(",
    
    r"imap_body\s*\(",
    r"imap_fetchbody\s*\(",
    r"imap_fetchheader\s*\(",
    r"imap_fetchstructure\s*\(",
    r"imap_search\s*\(",
    r"imap_sort\s*\(",
    r"imap_thread\s*\(",
    
    r"exif_read_data\s*\(",
    r"exif_thumbnail\s*\(",
    r"exif_imagetype\s*\(",
    
    r"easter_date\s*\(",
    r"easter_days\s*\(",
    r"unixtojd\s*\(",
    r"jdtounix\s*\(",
    r"cal_to_jd\s*\(",
    r"cal_from_jd\s*\(",
    
    r"getservbyname\s*\(",
    r"getservbyport\s*\(",
    r"getprotobyname\s*\(",
    r"getprotobynumber\s*\(",
    r"inet_ntop\s*\(",
    r"inet_pton\s*\(",
]

HIGH_RISK_PATTERNS = [
    r"fsockopen\s*\(",
    r"pfsockopen\s*\(",
    r"socket_create\s*\(",
    r"socket_connect\s*\(",
    r"socket_bind\s*\(",
    r"socket_listen\s*\(",
    r"socket_accept\s*\(",
    r"stream_socket_server\s*\(",
    r"stream_socket_client\s*\(",
    r"stream_socket_accept\s*\(",
    
    r"c99shell",
    r"r57shell",
    r"b374k\s*shell",
    r"wso\s*shell",
    r"liteshell",
    r"cybershell",
    r"phpshell",
    r"simpshell",
    r"indoxploit",
    r"zehir\s*shell",
    r"predator\s*shell",
    r"aspx\s*shell",
    r"sadrazam",
    r"knight\s*shell",
    r"ghost\s*shell",
    
    r"backconnect",
    r"reverse[\s_]*shell",
    r"bind[\s_]*shell",
    r"meterpreter",
    r"web\s*delivery",
    r"download\s*and\s*execute",
    r"download\s*&\s*exec",
    
    r"cmdshell",
    r"webcmd",
    r"cmd[\s_]*shell",
    r"php[\s_]*shell",
    r"php[\s_]*cmd",
    r"webshell",
    r"web[\s_]*shell",
    r"system\s*shell",
    r"admin\s*shell",
    r"root\s*shell",
    
    r"backdoor",
    r"back[\s_]*door",
    r"hidden[\s_]*door",
    r"secret[\s_]*access",
    r"persistent[\s_]*access",
    r"remote[\s_]*admin",
    r"unauthorized[\s_]*access",
    
    r"remote[\s_]*code[\s_]*exec",
    r"rce[\s_]*vector",
    r"code[\s_]*injection",
    r"command[\s_]*injection",
    r"arbitrary[\s_]*code[\s_]*exec",
    
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[.*\]\s*\(",
    r"create_function\s*\(\s*.*\$_(GET|POST|REQUEST)",
    r"assert\s*\(\s*.*\$_(GET|POST|REQUEST)",
    r"preg_replace\s*\(.*/e.*\$_(GET|POST|REQUEST)",
    
    r"disable[\s_]*function",
    r"bypass[\s_]*disable",
    r"disable[\s_]*security",
    r"disable[\s_]*safe[\s_]*mode",
    r"open_basedir[\s_]*bypass",
    r"suhosin[\s_]*bypass",
    r"mod_security[\s_]*bypass",
    
    r"privilege[\s_]*escalation",
    r"privesc",
    r"local[\s_]*privilege",
    r"root[\s_]*privilege",
    r"admin[\s_]*privilege",
    r"sudo[\s_]*exploit",
    
    r"tunnel[\s_]*shell",
    r"port[\s_]*forward",
    r"ssh[\s_]*tunnel",
    r"proxy[\s_]*shell",
    r"gate[\s_]*shell",
    r"bridge[\s_]*shell",
    
    r"data[\s_]*exfiltration",
    r"exfiltrate",
    r"steal[\s_]*data",
    r"dump[\s_]*database",
    r"database[\s_]*dump",
    r"credit[\s_]*card[\s_]*dump",
    
    r"crypto[\s_]*miner",
    r"coin[\s_]*miner",
    r"xmrig",
    r"ccminer",
    r"cryptonight",
    r"monero[\s_]*miner",
    r"bitcoin[\s_]*miner",
    
    r"ransomware",
    r"ransom[\s_]*note",
    r"encrypt[\s_]*files",
    r"decrypt[\s_]*key",
    r"bitcoin[\s_]*payment",
    r"wallet[\s_]*address",
    
    r"trojan",
    r"banker[\s_]*trojan",
    r"spyware",
    r"keylogger",
    r"screen[\s_]*logger",
    r"form[\s_]*grabber",
    r"cookie[\s_]*stealer",
    
    r"web[\s_]*inject",
    r"iframe[\s_]*inject",
    r"javascript[\s_]*inject",
    r"form[\s_]*inject",
    r"malicious[\s_]*redirect",
    
    r"server[\s_]*takeover",
    r"server[\s_]*compromise",
    r"root[\s_]*server",
    r"vps[\s_]*control",
    r"dedicated[\s_]*server",
    
    r"sql[\s_]*injection",
    r"xss[\s_]*payload",
    r"lfi[\s_]*exploit",
    r"rfi[\s_]*payload",
    r"csrf[\s_]*exploit",
    r"xxe[\s_]*injection",
    r"ssrf[\s_]*exploit",
    
    r"mass[\s_]*scanner",
    r"auto[\s_]*exploit",
    r"auto[\s_]*hacker",
    r"vulnerability[\s_]*scanner",
    r"exploit[\s_]*pack",
    
    r"botnet",
    r"zombie[\s_]*network",
    r"ddos[\s_]*bot",
    r"spam[\s_]*bot",
    r"irc[\s_]*bot",
    
    r"ld_preload",
    r"ld_library_path",
    r"dlopen",
    r"dlsym",
    r"ld_linux",
    
    r"rootkit",
    r"kernel[\s_]*module",
    r"loadable[\s_]*kernel",
    r"lkm",
    r"ring0",
    r"ring3",
    
    r"memory[\s_]*injection",
    r"process[\s_]*hollowing",
    r"reflective[\s_]*dll",
    r"pe[\s_]*injection",
    
    r"eternalblue",
    r"wannacry",
    r"petya",
    r"notpetya",
    r"heartbleed",
    r"shellshock",
    r"drupalgeddon",
    r"wordpress[\s_]*exploit",
    
    r"redis[\s_]*exploit",
    r"mongodb[\s_]*exploit",
    r"memcached[\s_]*exploit",
    r"docker[\s_]*escape",
    r"kubernetes[\s_]*exploit",
    
    r"mysql[\s_]*udf",
    r"postgresql[\s_]*udf",
    r"mssql[\s_]*xp_cmdshell",
    r"oracle[\s_]*java",
    
    r"bios[\s_]*rootkit",
    r"bootkit",
    r"mbr[\s_]*virus",
    r"uefi[\s_]*rootkit",
    
    r"aws[\s_]*key",
    r"cloud[\s_]*metadata",
    r"google[\s_]*api[\s_]*key",
    r"azure[\s_]*credential",
    
    r"log[\s_]*poisoning",
    r"log[\s_]*injection",
    r"apache[\s_]*log",
    r"nginx[\s_]*log",
    
    r"phishing[\s_]*kit",
    r"fake[\s_]*login",
    r"credential[\s_]*harvester",
    r"password[\s_]*stealer",
    
    r"bruteforce",
    r"dictionary[\s_]*attack",
    r"password[\s_]*cracker",
    r"hash[\s_]*cracker",
    
    r"dns[\s_]*tunneling",
    r"dns[\s_]*exfiltration",
    r"domain[\s_]*fronting",
    r"cdn[\s_]*abuse",
    
    r"cache[\s_]*poisoning",
    r"web[\s_]*cache[\s_]*deception",
    r"cache[\s_]*injection",
    
    r"mail[\s_]*server[\s_]*exploit",
    r"ftp[\s_]*server[\s_]*exploit",
    r"smtp[\s_]*exploit",
    r"ssh[\s_]*exploit",
    
    r"arp[\s_]*spoofing",
    r"mac[\s_]*flooding",
    r"vlan[\s_]*hopping",
    r"stp[\s_]*attack",
    
    r"fileless[\s_]*malware",
    r"memory[\s_]*resident",
    r"process[\s_]*injection",
    r"living[\s_]*off[\s_]*the[\s_]*land",
    
    r"cpu[\s_]*miner",
    r"gpu[\s_]*miner",
    r"resource[\s_]*abuse",
    r"bandwidth[\s_]*theft",
    
    r"header[\s_]*injection",
    r"http[\s_]*header[\s_]*attack",
    r"host[\s_]*header[\s_]*attack",
    
    r"env[\s_]*variable[\s_]*injection",
    r"environment[\s_]*hijacking",
    
    r"session[\s_]*hijacking",
    r"session[\s_]*fixation",
    r"cookie[\s_]*poisoning",
    
    r"xml[\s_]*entity[\s_]*injection",
    r"xml[\s_]*external[\s_]*entity",
    r"xsl[\s_]*injection",
    
    r"http[\s_]*request[\s_]*smuggling",
    r"http[\s_]*response[\s_]*splitting",
    r"https[\s_]*strip",
    
    r"timing[\s_]*attack",
    r"side[\s_]*channel",
    r"power[\s_]*analysis",
    
    r"exploit[\s_]*db[\s_]*id",
    r"cve[\s_]*20\d{2}[-_]\d{4,5}",
    r"0day",
    r"zero[\s_]*day",
]

OBFUSCATION = [
    r"[a-zA-Z0-9+/]{200,}={0,2}",
    r"\$[a-zA-Z0-9_]{1,3}="
]

SUSPICIOUS_NAMES = [
    "c99", "r57", "b374k", "wso", "liteshell", "cybershell",
    "phpshell", "c100", "r99", "kral", "turkshell", "indoxploit",
    "antshell", "simpshell", "zehir", "predator", "aspxshell",
    "sadrazam", "knight", "ghost", "havij", "sqlmap", "weevely",
    
    "shell", "cmd", "backdoor", "webshell", "web-shell", "webshells",
    "webcmd", "cmd-shell", "php-shell", "phpcmd", "phpspy",
    "shellbot", "shells", "reverse-shell", "bind-shell",
    "mini-shell", "microshell", "nanoshell", "picoshell",
    "admin-shell", "root-shell", "system-shell", "terminal",
    
    "hack", "hacked", "hacker", "hacking", "haxor", "h4x0r",
    "exploit", "exploits", "exploitation", "0day", "zero-day",
    "crack", "cracker", "cracking", "keygen", "serial",
    "bypass", "bypasser", "backdoor", "backconnect",
    "malware", "malicious", "trojan", "virus", "worm",
    "ransomware", "spyware", "adware", "rootkit",
    
    "upload", "uploader", "file-upload", "upload-shell",
    "upl", "filemanager", "file-manager", "fm", "filemgr",
    "fileadmin", "adminfile", "tinyfilemanager", "phpfilemanager",
    "net2ftp", "ajaxfilemanager", "responsivefilemanager",
    "kcfinder", "ckfinder", "elfinder", "filebrowser",
    
    "admin", "administrator", "login", "logon", "signin",
    "panel", "adminpanel", "controlpanel", "cp", "dashboard",
    "wp-admin", "wp-login", "joomla-admin", "drupal-admin",
    "admin_login", "adminarea", "admin_area", "admin1",
    "admin888", "admin123", "admincp", "administratorcp",
    
    "scanner", "scanners", "dirbuster", "dirb", "gobuster",
    "nikto", "nmap", "metasploit", "sql-injection", "sqli",
    "xss", "lfi", "rfi", "csrf", "ssrf", "xxe",
    "brute", "bruteforce", "brute-force", "dictionary",
    "enumeration", "recon", "reconnaissance", "infogathering",
    
    "remote", "remoteshell", "remoteadmin", "remote-access",
    "teamviewer", "anydesk", "vnc", "rdp", "ssh", "telnet",
    "putty", "winscp", "filezilla", "tightvnc", "ultravnc",
    
    "hidden", "secret", "private", "confidential", "stealth",
    "cloak", "cloaked", "obfuscated", "encoded", "encrypted",
    "decoded", "decrypted", "base64", "rot13", "xor",
    "stego", "steganography", "invisible",
    
    "1337", "31337", "666", "999", "1234", "12345", "54321",
    "777", "888", "111", "222", "333", "444", "555",
    "6969", "8080", "10000", "65535", "27017", "3306",
    
    "php.gif", "php.jpg", "php.png", "php.jpeg",
    "jpg.php", "png.php", "gif.php", "jpeg.php",
    "txt.php", "pdf.php", "doc.php", "exe.php",
    
    "index.php.bak", "index.php.old", "index.php.backup",
    "wp-config.php.bak", "configuration.php.bak",
    "backup.sql", "dump.sql", "database.sql",
    "passwords.txt", "users.txt", "admins.txt",
    
    "eval-plugin", "exec-module", "system-widget",
    "backdoor-plugin", "shell-plugin", "malicious-addon",
    
    "cmd.exe", "powershell", "bash", "sh", "zsh",
    "nc.exe", "netcat", "wget.exe", "curl.exe",
    "python.exe", "perl.exe", "ruby.exe",
    
    "port", "ports", "ip", "address", "localhost",
    "127.0.0.1", "0.0.0.0", "192.168", "10.0", "172.16",
    
    "token", "api_key", "apikey", "secret_key", "privatekey",
    "password", "passwd", "pwd", "credentials", "auth",
    
    "error.log", "access.log", "debug.log", "install.log",
    "setup.log", "test.php", "debug.php", "test.php",
    
    "tmp.php", "temp.php", "cache.php", "session.php",
    "temp_shell.php", "tmp_cmd.php",
    
    "exploit.php", "inject.php", "sqli.php", "xss.php",
    "lfi.php", "rfi.php", "csrf.php",
    
    "sh3ll", "sh3l", "sh3l1", "cms", "sh3ll", "w3bsh3ll",
    "phpshell", "php-shell", "php-cmd", "php-backdoor",
    "mysql.php", "mysqldump.php", "phpmyadmin",
    
    "test.php", "check.php", "verify.php", "security.php",
    "pentest.php", "vuln.php", "vulnerability.php",
    
    "miner", "crypto", "cryptominer", "bitcoin", "monero",
    "xmrig", "ccminer", "mining", "cryptojacking",
    
    "redirect.php", "forward.php", "gate.php", "proxy.php",
    "bridge.php", "tunnel.php",
    
    "deface", "hacked_by", "h4cked_by", "owned",
    "hack3d", "defacement", "index_hacked",
    
    "readme.txt", "note.txt", "warning.txt", "alert.txt",
    "message.txt", "info.txt",
    
    "wp-backdoor.php", "wp-shell.php", "wp-cache.php",
    "wp-admin-shell.php", "wp-login-bypass.php",
    
    "joomla-shell.php", "joomla-backdoor.php",
    "joomla-exploit.php",
    
    "artisan-shell.php", "laravel-backdoor.php",
    "env-exploit.php",
    
    "hack_shodan", "hack_shodan", "shell_farsi",
    "backdoor_farsi", "upload_center", "login_admin",
]

PYTHON_SIGNATURES = [
    r"exec\s*\(",
    r"eval\s*\(",
    r"compile\s*\(.*exec",
    r"__import__\s*\(",
    r"getattr\s*\(.*__builtins__",
    r"setattr\s*\(.*__builtins__",
    r"delattr\s*\(.*__builtins__",
    
    r"os\.system\s*\(",
    r"os\.popen\s*\(",
    r"os\.popen2\s*\(",
    r"os\.popen3\s*\(",
    r"os\.popen4\s*\(",
    r"os\.spawn\w*\s*\(",
    r"os\.exec\w*\s*\(",
    r"os\.kill\s*\(",
    r"os\.fork\s*\(",
    
    r"subprocess\.Popen\s*\(",
    r"subprocess\.call\s*\(",
    r"subprocess\.check_call\s*\(",
    r"subprocess\.check_output\s*\(",
    r"subprocess\.run\s*\(",
    r"subprocess\.getoutput\s*\(",
    r"subprocess\.getstatusoutput\s*\(",
    
    r"platform\.platform\s*\(",
    r"platform\.system\s*\(",
    r"platform\.node\s*\(",
    r"platform\.release\s*\(",
    r"platform\.version\s*\(",
    r"platform\.machine\s*\(",
    r"platform\.processor\s*\(",
    
    r"base64\.b64decode\s*\(",
    r"base64\.b32decode\s*\(",
    r"base64\.b16decode\s*\(",
    r"base64\.a85decode\s*\(",
    r"base64\.b85decode\s*\(",
    r"codecs\.decode\s*\(.*base64",
    r"binascii\.a2b_base64\s*\(",
    r"binascii\.hexlify\s*\(",
    r"binascii\.unhexlify\s*\(",
    
    r"zlib\.decompress\s*\(",
    r"zlib\.decompressobj\s*\(",
    r"gzip\.decompress\s*\(",
    r"bz2\.decompress\s*\(",
    r"lzma\.decompress\s*\(",
    r"tarfile\.open\s*\(",
    r"zipfile\.ZipFile\s*\(",
    
    r"marshal\.loads\s*\(",
    r"marshal\.load\s*\(",
    r"pickle\.loads\s*\(",
    r"pickle\.load\s*\(",
    r"cPickle\.loads\s*\(",
    r"cPickle\.load\s*\(",
    r"json\.loads\s*\(.*__import__",
    r"yaml\.load\s*\(",
    r"yaml\.safe_load\s*\(",
    r"shelve\.open\s*\(",
    
    r"socket\.socket\s*\(",
    r"socket\.create_connection\s*\(",
    r"socket\.connect\s*\(",
    r"socket\.connect_ex\s*\(",
    r"socket\.bind\s*\(",
    r"socket\.listen\s*\(",
    r"socket\.accept\s*\(",
    r"ssl\.wrap_socket\s*\(",
    r"ssl\.SSLContext\s*\(",
    
    r"requests\.get\s*\(",
    r"requests\.post\s*\(",
    r"requests\.put\s*\(",
    r"requests\.delete\s*\(",
    r"requests\.head\s*\(",
    r"requests\.options\s*\(",
    r"requests\.Session\s*\(",
    r"urllib\.request\.urlopen\s*\(",
    r"urllib\.request\.Request\s*\(",
    r"urllib\.request\.urlretrieve\s*\(",
    r"httpx\.get\s*\(",
    r"httpx\.post\s*\(",
    r"aiohttp\.ClientSession\s*\(",
    r"http\.client\.HTTPConnection\s*\(",
    
    r"importlib\.import_module\s*\(",
    r"importlib\.__import__\s*\(",
    r"__import__\s*\(",
    r"imp\.load_module\s*\(",
    r"imp\.find_module\s*\(",
    r"imp\.load_source\s*\(",
    r"pkgutil\.find_loader\s*\(",
    r"pkgutil\.get_loader\s*\(",
    
    r"globals\s*\(",
    r"locals\s*\(",
    r"vars\s*\(",
    r"dir\s*\(",
    r"type\s*\(",
    r"isinstance\s*\(",
    r"issubclass\s*\(",
    r"callable\s*\(",
    r"hasattr\s*\(",
    r"getattr\s*\(",
    r"setattr\s*\(",
    r"delattr\s*\(",
    
    r"open\s*\(.*w.*\)",
    r"open\s*\(.*a.*\)",
    r"open\s*\(.*x.*\)",
    r"os\.remove\s*\(",
    r"os\.unlink\s*\(",
    r"os\.rmdir\s*\(",
    r"os\.removedirs\s*\(",
    r"shutil\.rmtree\s*\(",
    r"os\.rename\s*\(",
    r"os\.replace\s*\(",
    r"shutil\.move\s*\(",
    r"shutil\.copy\s*\(",
    r"shutil\.copy2\s*\(",
    
    r"multiprocessing\.Process\s*\(",
    r"multiprocessing\.Pool\s*\(",
    r"threading\.Thread\s*\(",
    r"threading\._start_new_thread\s*\(",
    r"concurrent\.futures\.ThreadPoolExecutor\s*\(",
    r"concurrent\.futures\.ProcessPoolExecutor\s*\(",
    
    r"ctypes\.cdll\s*\(",
    r"ctypes\.windll\s*\(",
    r"ctypes\.oledll\s*\(",
    r"ctypes\.cast\s*\(",
    r"ctypes\.pointer\s*\(",
    r"ctypes\.memmove\s*\(",
    r"ctypes\.memset\s*\(",
    r"mmap\.mmap\s*\(",
    
    r"cryptography\.hazmat\.",
    r"Crypto\.Cipher\.",
    r"Crypto\.PublicKey\.",
    r"hashlib\.",
    r"hmac\.",
    
    r"os\.environ\s*\[",
    r"os\.getenv\s*\(",
    r"os\.putenv\s*\(",
    r"os\.setenv\s*\(",
    r"os\.unsetenv\s*\(",
    r"os\.getcwd\s*\(",
    r"os\.chdir\s*\(",
    r"os\.chroot\s*\(",
    r"os\.chmod\s*\(",
    r"os\.chown\s*\(",
    
    r"ast\.parse\s*\(",
    r"ast\.literal_eval\s*\(",
    r"ast\.NodeTransformer\s*\(",
    r"ast\.NodeVisitor\s*\(",
    r"inspect\.getsource\s*\(",
    r"inspect\.getfile\s*\(",
    
    r"sys\.modules\s*\[",
    r"sys\.path\s*\.insert",
    r"sys\.path\s*\.append",
    r"sys\.setprofile\s*\(",
    r"sys\.settrace\s*\(",
    
    r"pyautogui\.",
    r"pynput\.",
    r"keyboard\.",
    r"mouse\.",
    
    r"PIL\.ImageGrab\s*\.grab\s*\(",
    r"mss\.mss\s*\(",
    r"pygetwindow\.",
    
    r"pyperclip\.copy\s*\(",
    r"pyperclip\.paste\s*\(",
    r"clipboard\.",
    
    r"pynput\.keyboard\.Listener\s*\(",
    r"keyboard\.hook\s*\(",
    r"keyboard\.on_press\s*\(",
    
    r"selenium\.webdriver\.",
    r"webbrowser\.open\s*\(",
    r"webbrowser\.open_new\s*\(",
    r"webbrowser\.open_new_tab\s*\(",
    
    r"sqlite3\.connect\s*\(",
    r"sqlite3\.Cursor\s*\(",
    r"psycopg2\.connect\s*\(",
    r"MySQLdb\.connect\s*\(",
    r"pymongo\.MongoClient\s*\(",
    
    r"smtplib\.SMTP\s*\(",
    r"smtplib\.SMTP_SSL\s*\(",
    r"email\.message\.",
    
    r"socket\.gethostbyname\s*\(",
    r"socket\.gethostbyaddr\s*\(",
    r"socket\.getaddrinfo\s*\(",
    
    r"time\.time\s*\(",
    r"time\.sleep\s*\(",
    r"datetime\.datetime\s*\.now\s*\(",
    r"datetime\.datetime\s*\.utcnow\s*\(",
    
    r"\.pyc",
    r"\.pyo",
    r"\.pyd",
    r"\.so",
    r"\.dll",
    r"cythonize\s*\(",
    r"nuitka\s*\(",
    r"pyinstaller\s*\(",
    
    r"eval\(compile\(",
    r"exec\(__import__\(",
    r"getattr\(__builtins__",
    r"lambda.*:.*exec",
    
    r"winreg\.",
    r"wmi\.",
    r"pywin32\.",
    r"comtypes\.",
    
    r"pwd\.",
    r"grp\.",
    r"spwd\.",
    r"crypt\.",
    
    r"dis\.dis\s*\(",
    r"dis\.get_instructions\s*\(",
    r"byteplay\.",
    r"capstone\.",
    r"keystone\.",
    
    r"cpuid\.",
    r"virt-what",
    r"wmi\.Win32_ComputerSystem",
    
    r"os\.startfile\s*\(",
    r"os\.system\s*\(.*startup",
    r"shutil\.copy\s*\(.*Startup",
    r"winreg\.CreateKey\s*\(.*Run",
    
    r"ptrace\.",
    r"sys\.gettrace\s*\(",
    r"time\.clock\s*\(",
    r"time\.perf_counter\s*\(",
    
    r"inspect\.stack\s*\(",
    r"sys\._getframe\s*\(",
    r"sys\.exc_info\s*\(",
]

PYTHON_REVERSE_SHELL = [
    r"socket\.socket\s*\(\s*socket\.AF_INET\s*,\s*socket\.SOCK_STREAM\s*\)",
    r"socket\.socket\s*\(\)\.connect\s*\(\(\s*[\"'].*?[\"']\s*,\s*\d+\s*\)",
    r"socket\.create_connection\s*\(\(\s*[\"'].*?[\"']\s*,\s*\d+\s*\)",
    r"socket\.connect\s*\(\(\s*[\"'].*?[\"']\s*,\s*\d+\s*\)",
    r"socket\.connect_ex\s*\(\(\s*[\"'].*?[\"']\s*,\s*\d+\s*\)",
    
    r"connect\s*\(\(\s*['\"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['\"]\s*,\s*\d+\s*\)",
    r"connect\s*\(\(\s*['\"]0\.0\.0\.0['\"]\s*,\s*\d+\s*\)",
    r"connect\s*\(\(\s*['\"]127\.0\.0\.1['\"]\s*,\s*\d+\s*\)",
    r"connect\s*\(\(\s*['\"]localhost['\"]\s*,\s*\d+\s*\)",
    
    r"os\.dup2\s*\(",
    r"os\.dup\s*\(",
    r"sys\.stdin\.fileno\s*\(\s*\)",
    r"sys\.stdout\.fileno\s*\(\s*\)",
    r"sys\.stderr\.fileno\s*\(\s*\)",
    r"fileno\s*\(\s*\)\s*,\s*\d\s*\)",
    
    r"subprocess\.call\s*\(\s*\[\s*[\"']/bin/sh[\"']",
    r"subprocess\.Popen\s*\(\s*\[\s*[\"']/bin/sh[\"']",
    r"subprocess\.Popen\s*\(\s*[\"']/bin/sh[\"']",
    r"os\.system\s*\(\s*[\"']/bin/sh[\"']",
    r"os\.popen\s*\(\s*[\"']/bin/sh[\"']",
    
    r"/bin/(?:sh|bash|zsh|dash|ksh|tcsh|csh|fish)",
    r"/usr/bin/(?:sh|bash|zsh|dash|ksh|tcsh|csh|fish)",
    r"cmd\.exe",
    r"powershell",
    r"pwsh",
    r"/system/bin/sh",
    
    r"pty\.spawn\s*\(",
    r"pty\.fork\s*\(",
    r"pty\.openpty\s*\(",
    r"tty\.setraw\s*\(",
    r"tty\.setcbreak\s*\(",
    
    r"pseudo-terminal",
    r"interactive.*shell",
    r"shell.*interactive",
    r"tty.*shell",
    r"shell.*tty",
    
    r"exec\(.*decode\(.*base64.*socket",
    r"exec\(base64\.b64decode.*socket",
    r"eval\(.*decode\(.*socket",
    r"exec\(zlib\.decompress.*socket",
    r"exec\(marshal\.loads.*socket",
    
    r"python\s+-c\s+['\"].*socket.*connect.*['\"]",
    r"python\s+-c\s+['\"].*exec.*socket.*['\"]",
    r"__import__\s*\(['\"]os['\"]\)\.system.*socket",
    r"__import__\s*\(['\"]socket['\"]\)\.socket",
    
    r"requests\.get\s*\(\s*[\"'].*?[\"']\s*\)\.text\s*\)\s*\)",
    r"urllib\.request\.urlopen\s*\(\s*[\"'].*?[\"']\s*\)\.read\s*\(\s*\)\s*\)",
    r"eval\(requests\.get",
    r"exec\(urllib\.request\.urlopen",
    r"http://.*/shell",
    r"https://.*/cmd",
    
    r"socket\.gethostbyname\s*\(\s*[\"'].*?[\"']\s*\)",
    r"dns\.resolver\s*\.query",
    r"dnspython",
    
    r"socket\.SOCK_RAW",
    r"socket\.IPPROTO_ICMP",
    r"ICMP.*shell",
    
    r"socket\.bind\s*\(\(\s*[\"'].*?[\"']\s*,\s*\d+\s*\)\)",
    r"socket\.listen\s*\(\s*\d+\s*\)",
    r"socket\.accept\s*\(\s*\)",
    r"bind.*shell",
    r"listening.*port",
    
    r"ssl\.wrap_socket\s*\(",
    r"ssl\.SSLContext\s*\(\s*\)\.wrap_socket",
    r"ssl\.create_default_context\s*\(\s*\)",
    r"socket\.socket.*ssl",
    
    r"threading\.Thread\s*\(.*socket",
    r"threading\._start_new_thread\s*\(.*shell",
    r"multiprocessing\.Process\s*\(.*shell",
    r"concurrent\.futures.*shell",
    
    r"websocket.*connect",
    r"websockets\.connect",
    r"ws://.*/shell",
    r"wss://.*/cmd",
    
    r"bash\s+-i\s*>\s*&",
    r"/dev/tcp/",
    r"/dev/udp/",
    r"nc\s+-e",
    r"netcat\s+-e",
    r"ncat\s+-e",
    r"socat\s+.*TCP:",
    
    r"ctypes\.cdll.*libc.*execve",
    r"mmap\.mmap.*shellcode",
    r"shellcode.*injection",
    
    r"memfd_create",
    r"fexecve",
    r"/proc/self/fd/",
    
    r"while\s+True:.*sendall.*recv",
    r"while\s+1:.*socket",
    r"for\s+line\s+in\s+iter\(.*recv.*socket",
    
    r"C2.*server",
    r"command.*control",
    r"beacon.*checkin",
    r"callback.*interval",
    
    r"while\s+True:.*try:.*except:.*sleep",
    r"try:.*connect.*except.*sleep.*continue",
    r"reconnect.*loop",
    
    r"socket\.sendall\(.*open\(.*read\(\)",
    r"socket\.send\(.*file.*read",
    r"send\(.*keyboard",
    r"send\(.*screenshot",
    
    r"__import__\(['\"]socket['\"]\)\.__dict__\[['\"]socket['\"]\]",
    r"getattr\(__import__\s*\(['\"]socket['\"]\),\s*['\"]socket['\"]\)",
    
    r"eval\(compile\(.*socket.*['\"]\)",
    r"exec\(.*decode\(.*['\"]\\x[0-9a-f]{2}.*['\"]\)",
    r"getattr\(__builtins__, ['\"]exec['\"]\)\(.*socket\)",
    
    r"os\.environ\[['\"]RHOST['\"]\]",
    r"os\.environ\[['\"]RPORT['\"]\]",
    r"os\.getenv\(['\"]LHOST['\"]\)",
    r"os\.getenv\(['\"]LPORT['\"]\)",
    
    r"4444", r"4443", r"5555", r"6666", r"7777", r"8080", r"9001", 
    r"1337", r"31337", r"12345", r"54321", r"65535",
    
    r"0x[a-f0-9]{8}",
    r"0o[0-7]{11}",
    r"int\s*\(\s*['\"][0-9]{10}['\"]\s*\)",
    
    r"connect\(\(['\"].*?\.(?:com|net|org|ir|ru|cn)['\"],\s*\d+\)",
    r"gethostbyname\(['\"].*?['\"]\)",
    
    r"service.*shell",
    r"shell.*service",
    r"remote.*shell",
    r"shell.*remote",
    
    r"RHOST\s*=",
    r"RPORT\s*=",
    r"LHOST\s*=",
    r"LPORT\s*=",
    r"IP_ADDRESS\s*=",
    r"PORT\s*=",
    
    r"def\s+reverse_shell",
    r"def\s+connect_back",
    r"def\s+backdoor",
    r"def\s+bind_shell",
    r"def\s+shell_listener",
    
    r"#.*reverse.*shell",
    r"#.*back.*connect",
    r"#.*bind.*port",
    r"#.*listening.*on.*port",
    
    r"exec\(.*requests\.get.*text\)",
    r"eval\(.*urllib\.request.*read\(\)\)",
    r"__import__\s*\(['\"]urllib['\"]\)\.request\.urlopen",
    
    r"sleep\s*\(\s*\d+\s*\)",
    r"time\.sleep\s*\(",
    r"random\.sleep",
    r"jitter",
    r"beacon",
    
    r"try:.*except.*ConnectionError",
    r"try:.*except.*socket\.error",
    r"try:.*connect.*except.*Exception",
    
    r"if.*connected.*else.*alternative",
    r"try.*socket.*except.*try.*http",
    r"fallback.*connection",
    
    r"subprocess\.Popen\(['\"]powershell['\"]",
    r"os\.system\(['\"]cmd\.exe['\"]",
    r"ctypes\.windll\.kernel32",
    
    r"/proc/self/exe",
    r"/bin/busybox",
    
    r"osascript",
    r"open.*-a.*Terminal",
    
    r"/system/bin/sh",
    r"Runtime\.getRuntime\(\)\.exec",
    
    r"os\.setuid\s*\(\s*0\s*\)",
    r"os\.setgid\s*\(\s*0\s*\)",
    r"sudo.*shell",
    r"su.*-c",
    
    r"['\"]python.*-c.*socket.*['\"]",
    r"['\"].*import socket.*['\"]",
    r"['\"].*exec.*connect.*['\"]",
    
    r"b64decode\(['\"][A-Za-z0-9+/=]{100,}['\"]\)",
    r"decode\(['\"]base64['\"],\s*['\"][A-Za-z0-9+/=]{100,}['\"]\)",
]


SHELL_SIGNATURES = [
    r"bash\s+-i\s*>\s*&",
    r"bash\s+-c\s*['\"].*?/dev/tcp/",
    r"bash\s+>&\s*/dev/tcp/",
    r"bash\s+0>&1",
    r"bash\s+1>&0",
    r"bash\s+2>&1",
    r"bash\s+5<>/dev/tcp/",
    
    r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,5}",
    r"/dev/udp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,5}",
    r"exec\s+5<>/dev/tcp/",
    r"exec\s+/dev/tcp/",
    r"cat\s+<&5\s*>&5",
    r"0<&196;exec 196<>/dev/tcp/",
    
    r"nc\s+-e\s+/bin/(?:sh|bash)",
    r"nc\s+-\s+/bin/(?:sh|bash)",
    r"nc\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,5}\s+-e",
    r"ncat\s+-e\s+/bin/(?:sh|bash)",
    r"netcat\s+-e\s+/bin/(?:sh|bash)",
    r"nc\.exe\s+-e",
    r"nc\s+-c\s+/bin/(?:sh|bash)",
    
    r"nc\s+-l\s+-p\s+\d{1,5}\s+-e",
    r"nc\s+-l\s+-v\s+-p\s+\d{1,5}\s+-e",
    r"nc\s+-l\s+-p\s+\d{1,5}\s+-c",
    
    r"nc\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,5}\s*<&1",
    r"nc\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,5}\s*|",
    r"rm\s+/tmp/f;mkfifo\s+/tmp/f;cat\s+/tmp/f|",
    
    r"mkfifo\s+.*/dev/tcp/",
    r"mkfifo\s+.*&&\s*nc\s+",
    r"mknod\s+.*p\s*&&\s*nc\s+",
    r"rm\s+.*fifo.*;mkfifo\s+.*fifo",
    r"fifo.*nc.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    
    r"socat\s+TCP:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\s+EXEC:/bin/(?:sh|bash)",
    r"socat\s+TCP-LISTEN:\d{1,5}\s+EXEC:/bin/(?:sh|bash)",
    r"socat\s+TCP4:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\s+EXEC:",
    r"socat\s+UDP4:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\s+EXEC:",
    r"socat\s+SSL:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\s+EXEC:",
    
    r"telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,5}\s*<&1",
    r"telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,5}\s*|\s*/bin/(?:sh|bash)",
    r"mknod\s+backpipe\s+p\s*&&\s*telnet\s+",
    
    r"openssl\s+s_client\s+-connect\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}",
    r"openssl\s+s_server\s+-accept\s+\d{1,5}\s+-cert",
    
    r"php\s+-r\s*['\"].*?fsockopen.*?['\"]",
    r"php\s+-r\s*['\"].*?system.*?['\"]",
    r"php\s+-r\s*['\"].*?exec.*?['\"]",
    
    r"python\s+-c\s*['\"].*?socket.*?['\"]",
    r"python\s+-c\s*['\"].*?subprocess.*?['\"]",
    r"python3?\s+-c\s*['\"].*?import socket.*?['\"]",
    
    r"perl\s+-e\s*['\"].*?socket.*?['\"]",
    r"perl\s+-MIO\s+-e",
    r"perl\s+-MIO::Socket::INET\s+-e",
    
    r"ruby\s+-rsocket\s+-e",
    r"ruby\s+-rsocket\s+-ropen-uri\s+-e",
    
    r"lua\s+-e\s*['\"].*?socket.*?['\"]",
    
    r"awk\s*'BEGIN.*socket.*'",
    
    r"powershell\s+-c\s*['\"].*?Net\.Sockets.*?['\"]",
    r"powershell\s+-enc\s+",
    r"powershell\s+iex\s*\(New-Object\s+Net\.WebClient\)\.DownloadString",
    
    r"wget\s+.*\s+-O\s+.*(?:sh|py|pl|php)",
    r"curl\s+.*\s+-o\s+.*(?:sh|py|pl|php)",
    r"fetch\s+.*\s+-o\s+.*(?:sh|py|pl|php)",
    r"axel\s+.*\s+-o\s+.*(?:sh|py|pl|php)",
    
    r"base64\s+-d",
    r"base64\s+--decode",
    r"echo\s+.*\s*\\|\s*base64\s+-d",
    r"echo\s+.*\s*\\|\s*base64\s+--decode",
    r"openssl\s+base64\s+-d",
    r"openssl\s+base64\s+-A\s+-d",
    
    r"xxd\s+-r\s+-p",
    r"hexdump\s+-C",
    r"echo\s+.*\s*\\|\s*xxd\s+-r\s+-p",
    
    r"eval\s*['\"].*?['\"]",
    r"eval\s+\$\(.*?\)",
    r"eval\s+`.*?`",
    r"exec\s+.*?&",
    r"source\s+.*?&",
    r"\.\s+.*?&",
    
    r"\$\(.*?\)",
    r"`.*?`",
    r"\$\\{.*?\\}",
    
    r"chmod\s+\+[xs]\s+.*",
    r"chmod\s+755\s+.*",
    r"chmod\s+777\s+.*",
    r"chmod\s+u\+[xs]\s+.*",
    r"chmod\s+a\+[xs]\s+.*",
    r"chmod\s+4755\s+.*",
    r"chmod\s+6755\s+.*",
    
    r"chown\s+root:root",
    r"chgrp\s+root\s+.*",
    
    r"echo\s+.*>\s*.*\.(?:sh|py|pl|php)",
    r"cat\s+>\s*.*\.(?:sh|py|pl|php)\s*<<",
    r"printf\s+.*>\s*.*\.(?:sh|py|pl|php)",
    r"touch\s+.*\.(?:sh|py|pl|php)",
    
    r"cat\s*>\s*.*\s*<<\s*['\"]?EOF['\"]?",
    r"cat\s*>\s*.*\s*<<\s*['\"]?EOFF['\"]?",
    r"cat\s*>\s*.*\s*<<\s*_EOF_",
    
    r"&\s*$",
    r"nohup\s+.*&",
    r"disown\s+.*&",
    r"setsid\s+.*&",
    
    r".*\s*\\|\s*.*\s*\\|\s*.*\s*\\|\s*.*",
    r".*\s*>\s*.*\s*2>&1",
    r".*\s*>&\s*.*",
    r".*\s*<\s*.*",
    
    r"ifconfig\s+.*\s*\\|\s*grep\s+inet",
    r"ip\s+addr\s+show",
    r"netstat\s+-an",
    r"netstat\s+-tulpn",
    r"ss\s+-tulpn",
    r"lsof\s+-i",
    
    r"nc\s+-z\s+-v\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,5}-\d{1,5}",
    r"nmap\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"masscan\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    
    r"sudo\s+.*/bin/(?:sh|bash)",
    r"su\s+-\s+-c",
    r"doas\s+.*/bin/(?:sh|bash)",
    
    r"find\s+.*-perm\s+-4000",
    r"find\s+.*-perm\s+-u=s",
    r"find\s+.*-type\s+f\s+-perm\s+-4000",
    
    r"crontab\s+-l",
    r"crontab\s+-e",
    r"echo\s+.*\s*\\|\s*crontab\s+-",
    r"systemctl\s+enable\s+.*",
    r"update-rc\.d\s+.*enable",
    r"chkconfig\s+.*on",
    
    r"script\s+-f\s+.*\.txt",
    r"tee\s+.*\.txt",
    r"xinput\s+.*test-xi2\s+--root",
    
    r"import\s+-window\s+root\s+.*\.png",
    r"scrot\s+.*\.png",
    r"gnome-screenshot\s+.*",
    
    r"tar\s+czf\s+-.*\s*\\|\s*curl\s+-X\s+POST",
    r"zip\s+-r\s+-.*\s*\\|\s*wget\s+--post-file",
    r"dd\s+if=.*\s*\\|\s*nc\s+",
    
    r"curl\s+-X\s+POST\s+-F\s+.*=@.*\.php",
    r"wget\s+--post-file=.*\.php",
    
    r"dig\s+.*\s*\\+\s*short\s+",
    r"nslookup\s+-query=.*",
    
    r"ping\s+-c\s+\d+\s+-p\s+.*",
    r"hping3\s+--icmp\s+--data",
    
    r"ssh\s+-f\s+-N\s+-L\s+",
    r"ssh\s+-f\s+-N\s+-R\s+",
    r"ssh\s+-D\s+\d{1,5}\s+",
    r"autossh\s+-M\s+\d+\s+-f\s+-N",
    
    r"openvpn\s+--config",
    r"wireguard\s+quick",
    r"pppd\s+call",
    
    r"arpspoof\s+-i\s+\w+\s+-t",
    r"ettercap\s+-T\s+-q\s+-M\s+arp",
    
    r"grep\s+-r\s+-i\s+password\s+",
    r"find\s+.*-name\s+.*\.txt\s+-exec\s+grep\s+-l\s+password",
    r"strings\s+.*\s*\\|\s*grep\s+-i\s+pass",
    
    r"unshadow\s+/etc/passwd\s+/etc/shadow",
    r"pwdump",
    r"gsecdump",
    
    r"gcore\s+\d+",
    r"dd\s+if=/proc/\d+/mem",
    
    r"sqlmap\s+-u\s+",
    r"nikto\s+-h\s+",
    r"gobuster\s+dir\s+-u\s+",
    r"dirb\s+",
    r"wfuzz\s+",
    
    r"xmrig",
    r"cpuminer",
    r"ccminer",
    r"./minerd",
    r"./cpuminer",
    
    r"\./bot",
    r"\./client",
    r"\./agent",
    
    r"shred\s+-u\s+",
    r"wipe\s+-f\s+",
    r"dd\s+if=/dev/urandom\s+of=",
    r"rm\s+-rf\s+",
    
    r">\s+/var/log/",
    r"echo\s+''\s*>\s*/var/log/",
    r"logrotate\s+-f",
    
    r"insmod\s+",
    r"modprobe\s+",
    r"depmod\s+",
    
    r"docker\s+run\s+--privileged",
    r"docker\s+exec\s+-it\s+",
    r"runc\s+exec\s+",
    
    r"reg\s+add",
    r"schtasks\s+/create",
    r"wmic\s+process\s+call\s+create",
    r"powershell\s+Start-Process",
    
    r"osascript\s+-e",
    r"launchctl\s+load",
    r"defaults\s+write",
    
    r"am\s+start",
    r"pm\s+install",
    r"input\s+keyevent",
    
    r"\$\\{IFS\\}",
    r"\\\$@",
    r"\\\$\\(\\\$\\(\\\$\\(.*\\)\\)\\)",
    r"\\x[0-9a-f]{2}",
    r"\\\\[0-7]{3}",
    
    r"\$\{SHELL\}",
    r"\$\{SH\}",
    r"\$\{0\}",
    r"\$\{_\}",
    
    r"\\u[0-9a-f]{4}",
    r"\\U[0-9a-f]{8}",
    
    r"alias\s+.*=.*rm",
    r"alias\s+.*=.*chmod",
    r"alias\s+.*=.*nc",
    
    r"gdb\s+-p\s+\d+\s+-ex",
    r"strace\s+-f\s+-p\s+\d+",
    r"inject\s+",
    
    r"kill\s+-STOP",
    r"kill\s+-CONT",
    r"trap\s+''\s+",
    
    r"exec\s+\d<>/dev/tcp/",
    r".\s+/dev/(?:tcp|udp)/",
    
    r"memfd_create",
    r"fexecve",
    
    r"steghide\s+embed",
    r"steghide\s+extract",
    r"outguess\s+-r",
    
    r"sleep\s+\d+",
    r"usleep\s+\d+",
    r"timeout\s+\d+",
    
    r"ping\s+-s\s+\d+\s+",
    r"traceroute\s+",
    r"mtr\s+",
    
    r"dd\s+if=/dev/mem",
    r"cat\s+/proc/cpuinfo",
    r"dmidecode",
    
    r"flashrom",
    r"efibootmgr",
    
    r"dmesg\s*\\|\s*grep\s+-i\s+(?:vmware|virtualbox|kvm|qemu)",
    r"systemd-detect-virt",
    
    r"strace\s+-e\s+trace=none",
    r"ltrace\s+-e\s+",
    
    r"gcc\s+-o\s+.*\.c",
    r"make\s+",
    r"cmake\s+",
    
    r"#!/bin/(?:sh|bash).*\\n.*exec",
    r"#!/usr/bin/env.*python.*\\n.*import socket",
    r"#!/usr/bin/php.*\\n.*system\s*\(",
]

SHELL_DANGEROUS_CMDS = [
    r"rm\s+-rf\s+/(?:\s|$)",
    r"rm\s+-rf\s+/\.(?:\s|$)",
    r"rm\s+--no-preserve-root\s+-rf\s+/",
    r"rm\s+-rf\s+/boot",
    r"rm\s+-rf\s+/etc",
    r"rm\s+-rf\s+/home",
    r"rm\s+-rf\s+/usr",
    r"rm\s+-rf\s+/var",
    r"rm\s+-rf\s+/lib",
    r"rm\s+-rf\s+/opt",
    r"rm\s+-rf\s+/srv",
    r"rm\s+-rf\s+/sys",
    r"rm\s+-rf\s+/proc",
    r"rm\s+-rf\s+/dev",
    r"rm\s+-rf\s+/run",
    r"rm\s+-rf\s+/tmp",
    
    r"rm\s+-rf\s+\*",
    r"rm\s+-rf\s+\.\*",
    r"rm\s+-rf\s+\*\.\*",
    r"rm\s+-rf\s+\.[^.]\S*",
    
    r"dd\s+if=(?:/dev/zero|/dev/urandom|/dev/random)\s+of=/dev/(?:sd[a-z]|hd[a-z]|nvme\d+n\d+|vd[a-z]|mmcblk\d+)",
    r"dd\s+if=\.\.\.\s+of=/dev/(?:sd[a-z]|hd[a-z]|nvme\d+n\d+|vd[a-z]|mmcblk\d+)",
    r"dd\s+if=/dev/(?:zero|urandom|random)\s+of=",
    r"dd\s+if=/dev/(?:zero|urandom|random)\s+bs=\d+\s+count=\d+\s+of=",
    
    r"dd\s+if=/dev/(?:zero|urandom|random)\s+of=/dev/(?:sd[a-z]|hd[a-z]|nvme\d+n\d+|vd[a-z]|mmcblk\d+)\s+bs=\d+\s+count=\d+",
    r"dd\s+if=/dev/(?:zero|urandom|random)\s+of=/dev/(?:sd[a-z]|hd[a-z]|nvme\d+n\d+|vd[a-z]|mmcblk\d+)\s+seek=\d+",
    
    r"mkfs\.(?:ext[234]|xfs|btrfs|vfat|ntfs|f2fs)\s+/dev/(?:sd[a-z]\d*|hd[a-z]\d*|nvme\d+n\d+p\d+|vd[a-z]\d*|mmcblk\d+p\d+)",
    r"mke2fs\s+/dev/",
    r"mkdosfs\s+/dev/",
    r"mkfs\s+-t\s+\w+\s+/dev/",
    r"format\s+/dev/",
    
    r"mkfs\.(?:ext[234]|xfs|btrfs)\s+/dev/(?:sd[a-z]\d+|hd[a-z]\d+|nvme\d+n\d+p\d+|vd[a-z]\d+|mmcblk\d+p\d+)",
    
    r"mdadm\s+--stop\s+/dev/md\d+",
    r"mdadm\s+--zero-superblock\s+/dev/(?:sd[a-z]|hd[a-z]|nvme\d+n\d+|vd[a-z]|mmcblk\d+)",
    r"vgremove\s+\S+",
    r"lvremove\s+\S+",
    r"pvremove\s+/dev/",
    
    r"useradd\s+(?:-ou\s+0|-g\s+0|-G\s+(?:root|wheel|sudo))\s+\S+",
    r"useradd\s+-D\s+-s\s+/bin/(?:bash|sh)",
    r"useradd\s+.*-p\s+\S+",
    r"useradd\s+.*--password\s+\S+",
    r"useradd\s+-o\s+-u\s+0\s+-g\s+0\s+\S+",
    
    r"useradd\s+-r\s+-s\s+/bin/(?:bash|sh)\s+\S+",
    r"useradd\s+--system\s+--shell\s+/bin/(?:bash|sh)\s+\S+",
    
    r"usermod\s+-aG\s+(?:root|wheel|sudo)\s+\S+",
    r"usermod\s+-ou\s+0\s+\S+",
    r"usermod\s+-s\s+/bin/(?:bash|sh)\s+\S+",
    r"usermod\s+-p\s+\S+\s+\S+",
    
    r"userdel\s+-rf?\s+(?:root|admin|administrator)",
    r"userdel\s+-r\s+\S+",
    
    r"groupadd\s+(?:root|wheel|sudo|admin)",
    r"groupmod\s+-g\s+0\s+\S+",
    r"groupdel\s+(?:root|wheel|sudo|admin)",
    
    r"passwd\s+(?:root|admin)",
    r"echo\s+\".*\"\s*\\|\s*chpasswd",
    r"echo\s+\".*\"\s*\\|\s*passwd\s+--stdin",
    r"openssl\s+passwd.*\\|\s*chpasswd",
    
    r"chown\s+(?:-R\s+)?(?:root:|0:0)\s+/",
    r"chown\s+(?:-R\s+)?(?:root:|0:0)\s+/etc",
    r"chown\s+(?:-R\s+)?(?:root:|0:0)\s+/bin",
    r"chown\s+(?:-R\s+)?(?:root:|0:0)\s+/sbin",
    r"chown\s+(?:-R\s+)?(?:root:|0:0)\s+/usr",
    
    r"chmod\s+(?:-R\s+)?[0-7]{3,4}\s+/",
    r"chmod\s+777\s+/",
    r"chmod\s+4755\s+/",
    r"chmod\s+6755\s+/",
    r"chmod\s+u\+[sx]\s+/",
    r"chmod\s+a\+[sx]\s+/",
    r"chmod\s+[0-7]{3,4}\s+/etc/passwd",
    r"chmod\s+[0-7]{3,4}\s+/etc/shadow",
    r"chmod\s+[0-7]{3,4}\s+/etc/sudoers",
    
    r"echo\s+.*\s*>>\s*/etc/passwd",
    r"echo\s+.*\s*>>\s*/etc/shadow",
    r"cat\s*>>\s*/etc/passwd",
    r"cat\s*>>\s*/etc/shadow",
    r"sed\s+-i\s+'s/.*/.*/'\s+/etc/passwd",
    r"sed\s+-i\s+'s/.*/.*/'\s+/etc/shadow",
    
    r"echo\s+.*\s*>>\s*/etc/sudoers",
    r"cat\s*>>\s*/etc/sudoers",
    r"visudo\s+-c\s+-f",
    r"EDITOR=.*\s+visudo",
    
    r"iptables\s+-F",
    r"iptables\s+--flush",
    r"iptables\s+-X",
    r"iptables\s+-Z",
    r"iptables\s+-t\s+nat\s+-F",
    r"iptables\s+-t\s+mangle\s+-F",
    
    r"iptables\s+-P\s+INPUT\s+DROP",
    r"iptables\s+-P\s+OUTPUT\s+DROP",
    r"iptables\s+-P\s+FORWARD\s+DROP",
    
    r"nft\s+flush\s+ruleset",
    r"nft\s+delete\s+table",
    
    r"firewall-cmd\s+--panic-on",
    r"firewall-cmd\s+--remove-service=ssh",
    r"firewall-cmd\s+--remove-service=http",
    
    r"ufw\s+disable",
    r"ufw\s+--force\s+reset",
    
    r"shutdown\s+-h\s+now",
    r"shutdown\s+-r\s+now",
    r"shutdown\s+--poweroff\s+now",
    r"shutdown\s+--reboot\s+now",
    r"poweroff",
    r"reboot",
    r"halt",
    r"init\s+0",
    r"init\s+6",
    r"telinit\s+0",
    r"telinit\s+6",
    r"systemctl\s+poweroff",
    r"systemctl\s+reboot",
    r"systemctl\s+halt",
    
    r"killall\s+-9\s+-u\s+root",
    r"killall\s+-9\s+.*",
    r"pkill\s+-9\s+-u\s+root",
    r"pkill\s+-9\s+.*",
    r"kill\s+-9\s+-1",
    r"kill\s+--sigkill\s+--\s+-1",
    
    r":\(\)\{:\|:&\};:",
    r"fork\(\)\{fork\|fork&\};fork",
    r"\w+\(\)\{\w+\|\w+&\};\w+",
    
    r"swapoff\s+-a",
    r"swapon\s+--discard",
    r"echo\s+1\s*>\s*/proc/sys/vm/drop_caches",
    r"sync; echo 3 > /proc/sys/vm/drop_caches",
    
    r">\s+/var/log/(?:auth\.log|secure|messages|syslog|daemon\.log)",
    r"rm\s+-f\s+/var/log/.*\.log",
    r"journalctl\s+--vacuum-time=\d+[dhms]",
    r"logrotate\s+-f",
    
    r"date\s+-s\s+'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'",
    r"timedatectl\s+set-time\s+'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'",
    r"hwclock\s+--systohc",
    
    r"echo\s+nameserver\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*>\s*/etc/resolv\.conf",
    r"chattr\s+\+i\s+/etc/resolv\.conf",
    
    r"hostnamectl\s+set-hostname\s+\S+",
    r"echo\s+.*\s*>\s*/etc/hostname",
    
    r"echo\s+1\s*>\s*/proc/sys/kernel/sysrq",
    r"sysctl\s+-w\s+kernel\.sysrq=1",
    r"echo\s+c\s*>\s*/proc/sysrq-trigger",
    r"echo\s+b\s*>\s*/proc/sysrq-trigger",
    
    r"umount\s+-f\s+-l\s+/",
    r"umount\s+-f\s+-l\s+/boot",
    r"umount\s+-a",
    r"mount\s+-o\s+remount,rw\s+/",
    r"mount\s+-t\s+tmpfs\s+-o\s+size=\d+[MG]\s+tmpfs\s+/",
    
    r"setenforce\s+0",
    r"setenforce\s+Permissive",
    r"sestatus",
    r"apparmor_parser\s+-R",
    r"aa-disable\s+\S+",
    
    r"echo\s+.*\s*>>\s*/root/\.ssh/authorized_keys",
    r"cat\s*>>\s*/root/\.ssh/authorized_keys",
    r"ssh-keygen\s+-t\s+rsa\s+-N\s+''\s+-f\s+/root/\.ssh/id_rsa",
    r"systemctl\s+stop\s+ssh[d]?",
    r"systemctl\s+disable\s+ssh[d]?",
    
    r"systemctl\s+stop\s+(?:cron|crond|atd|syslog|rsyslog|systemd-journald)",
    r"systemctl\s+disable\s+(?:cron|crond|atd|syslog|rsyslog|systemd-journald)",
    r"systemctl\s+mask\s+(?:cron|crond|atd|syslog|rsyslog|systemd-journald)",
    
    r"systemctl\s+set-default\s+multi-user\.target",
    r"systemctl\s+isolate\s+multi-user\.target",
    r"systemctl\s+daemon-reload",
    
    r"echo\s+.*\s*\\|\s*crontab\s+-",
    r"crontab\s+-r",
    r"crontab\s+-\S+\s+-r",
    
    r"curl\s+-sSL\s+http[s]?://.*\s*\\|\s*(?:sh|bash|python|perl|ruby)",
    r"wget\s+-qO-\s+http[s]?://.*\s*\\|\s*(?:sh|bash|python|perl|ruby)",
    r"fetch\s+-qo-\s+http[s]?://.*\s*\\|\s*(?:sh|bash|python|perl|ruby)",
    
    r"export\s+PATH=.*:/tmp",
    r"export\s+PATH=/tmp:.*",
    r"PATH=/tmp:\$PATH",
    
    r"cp\s+/bin/(?:sh|bash)\s+/tmp/",
    r"cp\s+/usr/bin/python\s+/tmp/",
    r"ln\s+-s\s+/bin/(?:sh|bash)\s+/tmp/",
    
    r"echo\s+\".*ALL=\(ALL\)\s+NOPASSWD:\s+ALL\"\s*>>\s*/etc/sudoers",
    r"echo\s+\".*\s+ALL=\(ALL:ALL\)\s+ALL\"\s*>>\s*/etc/sudoers\.d/",
    
    r"sed\s+-i\s+'s/^#*Port\s+\d+/Port\s+\d+/'\s+/etc/ssh/sshd_config",
    r"sed\s+-i\s+'s/^#*PermitRootLogin\s+.*/PermitRootLogin\s+yes/'\s+/etc/ssh/sshd_config",
    
    r"sed\s+-i\s+'s/^HostKey\s+.*//'\s+/etc/ssh/sshd_config",
    r"sed\s+-i\s+'s/^KexAlgorithms\s+.*//'\s+/etc/ssh/sshd_config",
    
    r"echo\s+\"auth\s+sufficient\s+pam_permit\.so\"\s*>>\s*/etc/pam\.d/",
    r"sed\s+-i\s+'s/^auth\s+required\s+pam_deny\.so/auth\s+sufficient\s+pam_permit\.so/'\s+/etc/pam\.d/",
    
    r"echo\s+net\.ipv4\.ip_forward=1\s*>>\s*/etc/sysctl\.conf",
    r"echo\s+kernel\.exec-shield=0\s*>>\s*/etc/sysctl\.conf",
    r"echo\s+kernel\.randomize_va_space=0\s*>>\s*/etc/sysctl\.conf",
    
    r"echo\s+0\s*>\s*/proc/sys/kernel/randomize_va_space",
    r"sysctl\s+-w\s+kernel\.randomize_va_space=0",
    
    r"echo\s+\"\\*\s+hard\s+nofile\s+65535\"\s*>>\s*/etc/security/limits\.conf",
    r"echo\s+\"\\*\s+soft\s+nproc\s+unlimited\"\s*>>\s*/etc/security/limits\.conf",
    
    r"auditctl\s+-e\s+0",
    r"service\s+auditd\s+stop",
    r"systemctl\s+stop\s+auditd",
    
    r"sed\s+-i\s+\"s/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\\\"console=tty0\\\"/\"\s+/etc/default/grub",
    r"update-grub",
    r"grub2-mkconfig\s+-o\s+/boot/grub2/grub\.cfg",
    
    r"mokutil\s+--disable-validation",
    r"efibootmgr\s+-t\s+0",
    
    r"dmidecode\s+-t\s+bios",
    r"flashrom\s+--write",
    
    r"setpci\s+-s\s+\S+\s+",
    r"lspci\s+-v",
    r"lsusb\s+-v",
    
    r"modprobe\s+-r\s+kvm",
    r"modprobe\s+-r\s+kvm_intel",
    r"modprobe\s+-r\s+kvm_amd",
    
    r"docker\s+rm\s+-f\s+\$(docker ps -aq)",
    r"docker\s+rmi\s+-f\s+\$(docker images -q)",
    r"docker\s+volume\s+prune\s+-f",
    
    r"kubectl\s+delete\s+--all\s+--all-namespaces",
    r"kubectl\s+delete\s+namespace\s+default",
    
    r"mysql\s+-e\s+\"DROP\s+DATABASE\s+.*\"",
    r"psql\s+-c\s+\"DROP\s+DATABASE\s+.*\"",
    r"mongo\s+--eval\s+\"db\.dropDatabase\(\)\"",
    
    r"find\s+/.*backup.*\s+-type\s+f\s+-delete",
    r"find\s+/.*\.bak\s+-type\s+f\s+-delete",
    r"find\s+/.*\.old\s+-type\s+f\s+-delete",
    
    r"systemctl\s+stop\s+(?:zabbix-agent|nagios-nrpe-server|prometheus)",
    r"killall\s+(?:zabbix_agentd|nrpe|node_exporter)",
    
    r"echo\s+''\s*>\s*/var/log/\*\.log",
    r"find\s+/var/log\s+-name\s+'\*\.log'\s+-exec\s+shred\s+{}",
    
    r"systemctl\s+stop\s+(?:clamav|rkhunter|chkrootkit|aide)",
    r"apt-get\s+remove\s+--purge\s+(?:clamav|rkhunter|chkrootkit|aide)",
    
    r"apt-get\s+remove\s+--purge\s+.*",
    r"yum\s+remove\s+-y\s+.*",
    r"dnf\s+remove\s+-y\s+.*",
    r"pacman\s+-Rscn\s+.*",
    
    r"systemctl\s+stop\s+(?:unattended-upgrades|dnf-automatic|yum-cron)",
    r"systemctl\s+disable\s+(?:unattended-upgrades|dnf-automatic|yum-cron)",
    
    r"rmmod\s+\S+",
    r"modprobe\s+-r\s+\S+",
    
    r"quotaoff\s+-a",
    r"quotacheck\s+-ugm",
    
    r"tune2fs\s+-c\s+0\s+/dev/",
    r"debugfs\s+-w\s+/dev/",
    
    r"cryptsetup\s+luksClose",
    r"cryptsetup\s+remove",
    
    r"mdadm\s+--stop\s+/dev/md",
    r"mdadm\s+--zero-superblock",
    
    r"lvremove\s+-f",
    r"vgremove\s+-f",
    r"pvremove\s+-f",
    
    r"smartctl\s+--offlineauto=off",
    r"smartctl\s+--smart=off",
    
    r"ifconfig\s+\S+\s+down",
    r"ip\s+link\s+set\s+\S+\s+down",
    r"nmcli\s+connection\s+delete",
    
    r"systemctl\s+stop\s+network",
    r"systemctl\s+stop\s+NetworkManager",
    
    r"ip\s+route\s+flush",
    r"route\s+del\s+default",
    
    r"echo\s+1\s*>\s*/proc/sys/net/ipv6/conf/all/disable_ipv6",
    r"sysctl\s+-w\s+net\.ipv6\.conf\.all\.disable_ipv6=1",
    
    r"chattr\s+\+i\s+/etc/resolv\.conf",
    r"rm\s+-f\s+/etc/resolv\.conf",
    
    r"systemctl\s+stop\s+ntp[d]?",
    r"timedatectl\s+set-ntp\s+false",
    
    r"localectl\s+set-locale\s+LANG=",
    r"update-locale\s+LANG=",
    
    r"gsettings\s+set\s+org\.gnome\.desktop\.screensaver\s+lock-enabled\s+false",
    r"xset\s+s\s+off",
    
    r"gsettings\s+set\s+org\.gnome\.desktop\.clipboard\s+saver\s+false",
]

SUSPICIOUS_PHP_EXTENSIONS = [
    ".php.gif", ".php.jpg", ".phtml", ".php3", ".php5", ".pht", ".phar"
]

SUSPICIOUS_IMAGE_EXTENSIONS = [
    ".ico", ".png", ".jpg", ".jpeg", ".gif"
]

def get_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()
    except:
        return None

def detect_python(code):
    alerts = []
    risk = 0

    for rule in PYTHON_SIGNATURES:
        if re.search(rule, code, re.IGNORECASE):
            alerts.append(f"[PY-MALWARE] Python suspicious pattern: {rule}")
            risk += 5

    for rule in PYTHON_REVERSE_SHELL:
        if re.search(rule, code):
            alerts.append("[CRITICAL] Python reverse shell detected")
            risk += 15

    if "import" in code and len(code.splitlines()) == 1:
        alerts.append("[PY-HIGH] One-line encoded Python payload")
        risk += 10

    return risk, alerts

def detect_shell(code):
    alerts = []
    risk = 0

    for rule in SHELL_SIGNATURES:
        if re.search(rule, code, re.IGNORECASE):
            alerts.append(f"[SH-MALWARE] Shell malicious pattern: {rule}")
            risk += 20

    for rule in SHELL_DANGEROUS_CMDS:
        if re.search(rule, code):
            alerts.append(f"[CRITICAL] Dangerous shell command: {rule}")
            risk += 40

    return risk, alerts

def detect_php_in_images(path, content):
    alerts = []
    risk = 0
    fname = os.path.basename(path).lower()

    for ext in SUSPICIOUS_PHP_EXTENSIONS:
        if fname.endswith(ext):
            alerts.append(f"[CRITICAL] Suspicious PHP file disguised: {fname}")
            risk += 40

    for ext in SUSPICIOUS_IMAGE_EXTENSIONS:
        if fname.endswith(ext):
            if "<?php" in content:
                alerts.append(f"[CRITICAL] PHP code inside image file: {fname}")
                risk += 50

    return risk, alerts

def scan_file(path, chunk_size=1024 * 512):
    if not os.path.isfile(path):
        return 0, [], None

    fname = os.path.basename(path).lower()

    image_ext = (".png", ".jpg", ".jpeg", ".gif", ".ico")
    code_ext = (".php", ".phtml", ".php3", ".php5", ".phar",
                ".py", ".sh", ".js", ".html", ".htm")

    is_image = fname.endswith(image_ext)
    is_code = fname.endswith(code_ext)

    alerts = []
    risk = 0

    sha256 = hashlib.sha256()

    try:
        with open(path, "rb") as f:

            buffer_text = ""

            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                sha256.update(chunk)

                try:
                    text = chunk.decode("utf-8", errors="ignore")
                except:
                    text = ""

                buffer_text += text

                if len(buffer_text) > 50000:
                    buffer_text = buffer_text[-20000:]

                if any(fname.endswith(ext) for ext in SUSPICIOUS_IMAGE_EXTENSIONS):
                    if "<?php" in buffer_text:
                        alerts.append("[CRITICAL] PHP code found inside image")
                        risk += 10

                if is_image:
                    continue

                if is_code:
                    for rule in DANGEROUS_FUNCTIONS:
                        if re.search(rule, buffer_text, re.IGNORECASE):
                            alerts.append(f"[HIGH] Dangerous API: {rule}")
                            risk += 1

                    for rule in HIGH_RISK_PATTERNS:
                        if re.search(rule, buffer_text, re.IGNORECASE):
                            alerts.append(f"[CRITICAL] Backdoor signature: {rule}")
                            risk += 4

                    for rule in OBFUSCATION:
                        if re.search(rule, buffer_text):
                            alerts.append(f"[HIGH] Obfuscation detected: {rule}")
                            risk += 4

                    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", buffer_text):
                        alerts.append("[MEDIUM] IP address seen")
                        risk += 1

                    if "connect" in buffer_text.lower():
                        alerts.append("[MEDIUM] Possible reverse shell connect()")
                        risk += 2

                if fname.endswith(".py"):
                    p_risk, p_alerts = detect_python(buffer_text)
                    risk += p_risk // 2
                    alerts.extend(p_alerts)

                if fname.endswith(".sh"):
                    s_risk, s_alerts = detect_shell(buffer_text)
                    risk += s_risk // 2
                    alerts.extend(s_alerts)

    except Exception as e:
        return 0, [f"Unreadable file: {e}"], None

    for bad in SUSPICIOUS_NAMES:
        if bad in fname:
            alerts.append(f"[HIGH] Suspicious filename: {fname}")
            risk += 4

    risk += len(alerts) * 1
    if risk > 100:
        risk = 100

    return risk, alerts, sha256.hexdigest()


def secure_quarantine_dir(path=None):
    global QUARANTINE_DIR
    if path is None:
        path = QUARANTINE_DIR

    if not path:
        raise ValueError("Quarantine directory not set!")

    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path


def quarantine_file(path, quarantine_dir=None):
    quarantine_dir = quarantine_dir or QUARANTINE_DIR

    if not quarantine_dir:
        raise ValueError("Quarantine directory not set!")

    secure_quarantine_dir(quarantine_dir)

    if not os.path.exists(path):
        return None

    sha = get_hash(path) or "unknown"

    filename = os.path.basename(path)
    safe_name = "".join(c for c in filename if c.isalnum() or c in "._-")
    if not safe_name:
        safe_name = "file"

    new_name = f"{int(time.time())}_{sha[:12]}_{safe_name}"
    dest = os.path.join(quarantine_dir, new_name)

    shutil.move(path, dest)

    os.chmod(dest, stat.S_IRUSR)

    return dest

