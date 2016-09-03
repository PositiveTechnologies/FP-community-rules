rule Dotclear_CMS_2_9_1
{
	// @exploit: http://0day.today/exploit/25267
	// @exploit: http://0day.today/exploit/25266
	meta:
			component_name = "Dotclear CMS"
            component_version = "2.9.1 and below"
            custom_title = "Dotclear CMS 2.9.1 and below Multiply Vulnerabilities"
            custom_level = "High" // High, Medium, Low
            custom_description = "<p>Dotclear has a feature to upload files in Media Manager. However, by default, there is a filtering to prevent authenticated users to upload malicious files, such PHP code, to execute on the server. The  filter does not filter .htaccess file which allows authenticated users to upload .htaccess file to the server which enable PHP code execution on any file extension.</p><p>Authenticated users with media manager access permission are allowed to download media directories in zip file format. The directory path to be zipped is not properly verified. As a result, it is possible for authenticated users with media manager access permission to download all directories readable by web server and located in the same traversal path as dotclear in zipped format. For example, if dotclear is located at /var/www/html/dotclear/ following directories can be downloaded if web server has read permission:</p><ul><li>/var/</li><li>/var/www/</li><li>/var/www/html/</li></ul><p>The authenticated users could have access to source code of dotclear, including config.php, and source code of other web application located under the same document root.</p><p>Fixed in version 2.10</p><p>Please download new version from <a href='http://www.dotclear.org/'>http://www.dotclear.org/</a></p>"
	strings:
			$v2_9_1 = "define('DC_VERSION','2.9"			
			$v2_8_2 = "define('DC_VERSION','2.8.2"
			$v2_8_1 = "define('DC_VERSION','2.8.1"
			$v2_8_0 = "define('DC_VERSION','2.8.0"
			$v2_7_5 = "define('DC_VERSION','2.7.5"
			$v2_7_4 = "define('DC_VERSION','2.7.4"
			$v2_7_3 = "define('DC_VERSION','2.7.3"
			$v2_7_2 = "define('DC_VERSION','2.7.2"
			$v2_7_1 = "define('DC_VERSION','2.7.1"
			$v2_6_4 = "define('DC_VERSION','2.6.4"
			$v2_6_3 = "define('DC_VERSION','2.6.3"
			$v2_6_2 = "define('DC_VERSION','2.6.2"
			$v2_6_1 = "define('DC_VERSION','2.6.1"
			$v2_6_0 = "define('DC_VERSION','2.6.0"
			$v2_6_RC = "define('DC_VERSION','2.6-RC"
			$v2_5_3 = "define('DC_VERSION','2.5.3"
			$v2_5_2 = "define('DC_VERSION','2.5.2"
			$v2_5_1 = "define('DC_VERSION','2.5.1"
			$v2_4_4 = "define('DC_VERSION','2.4.4"
			$v2_4_3 = "define('DC_VERSION','2.4.3"
			$v2_4_2 = "define('DC_VERSION','2.4.2"
			$v2_3_1 = "define('DC_VERSION','2.3.1"
			$v2_3_0 = "define('DC_VERSION','2.3.0"
	condition:
			php_file and Dotclear_CMS and any of ($v*)
}