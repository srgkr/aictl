<?php
/**
 * MOPAS SQL Injection Example 1
 * Fetch data from MySQL database using old mysql extension
 */
define('DB_HOST', '');
define('DB_PORT', 3306);
define('DB_USER', '');
define('DB_PASSWORD', '');
define('DB_NAME', '');

error_reporting(0);

if (empty($_POST['condition'])) {
	echo '<form action="" method="POST">
		Get items by condition: <input type="text" name="condition"/>
		<input type="submit" name="submit" value="Submit"/>
	</form>';
	exit;
}

if (mysql_connect(DB_HOST . ':' . DB_PORT, DB_USER, DB_PASSWORD) === FALSE) {
	die('Could not connect to database');
}

if (mysql_select_db(DB_NAME) === FALSE) {
	die('Could not select database');
}

if (mysql_set_charset('utf8') === FALSE) {
	die('Unable to set the character set');
}

$condition = $_POST['condition'];

$query = "SELECT * FROM items WHERE $condition";

$result = mysql_query($query);

if ($result === FALSE) {
	die('Query error.');
}

$numRows = mysql_num_rows($result);

if ($numRows === FALSE || $numRows === 0) {
	die('No item for you with this name.');
}

while($itemInfo = mysql_fetch_assoc($result)) {
	echo "owner: {$itemInfo['owner']}\n";
}
?>