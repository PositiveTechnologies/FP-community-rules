private rule php_file
{
	meta:
			custom_description = "Private rule for identifying php files"
	strings:
			$start = /^<\?php/ nocase
	condition:
			$start
}

private rule PHPMailer
{
	meta:
			custom_description = "Private rule for indentifying PHPMailer class"
	strings:
			$PHPMailer = "* @package PHPMailer"
	condition:
			$PHPMailer
}

private rule vBulletin
{
	meta:
			custom_description = "Private rule for indentifying vBulletin"
	strings:
			$package = "* @package vBulletin"
	condition:
			$package
}
