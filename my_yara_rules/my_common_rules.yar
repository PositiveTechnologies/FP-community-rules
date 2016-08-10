private rule php_file
{
	meta:
			custom_description = "Private rule for identifying php files"
	strings:
			$start = /^<\?php/ nocase
			$end = /\?>$/ nocase
	condition:
			$start or $end
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