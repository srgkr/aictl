<?php
/**
 *  MOPAS OS Command Injection Example 1
 *  Resolve site name into IP address
 */
if (empty($_GET['domain'])) {
	die('no domain');
}

$domain = $_GET['domain'];
system("nslookup $domain");
?>