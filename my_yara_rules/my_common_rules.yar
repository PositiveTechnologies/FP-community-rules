private rule php_file
{
	meta:
			custom_description = "Private rule for identifying php files"
	strings:
			$start = /^<\?php/ nocase
	condition:
			$start
}

private rule xml_file
{
	meta:
			custom_description = "Private rule for identifying xml files"
	strings:
			$start = /^<\?xml/ nocase
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

private rule YiiFramework
{
	meta:
			custom_description = "Private rule for indentifying YiiFramework"
	strings:
			$baseyii = /class BaseYii/ nocase
	condition:
			$baseyii
}

private rule com_aicontactsafe
{
	// @product = "Joomla"
	// @product_root = "../../../"
	// @marker_file = "/administrator/components/com_aicontactsafe/aicontactsafe.xml"
	
	meta:
			custom_description = "Private rule for indentifying aicontactsafe component from Joomla CMS"
	strings:
			$name = /<name>aiContactSafe<\/name>/ nocase
	condition:	
			$name
}

private rule com_theatre
{
	// @product = "Joomla"
	// @product_root = "../../../"
	// @marker_file = "/administrator/components/com_theatre/theatre.xml"
	
	meta:
			custom_description = "Private rule for indentifying com_theatre component from Joomla CMS"
	strings:
			$name = /<name>iC\s+agenda<\/name>/ nocase
	condition:	
			$name
}