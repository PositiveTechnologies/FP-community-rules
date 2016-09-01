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
			custom_description = "Private rule for identifying PHPMailer class"
	strings:
			$PHPMailer = "* @package PHPMailer"
	condition:
			$PHPMailer
}

private rule vBulletin
{
	meta:
			custom_description = "Private rule for identifying vBulletin"
	strings:
			$package = "* @package vBulletin"
	condition:
			$package
}

private rule YiiFramework
{
	meta:
			custom_description = "Private rule for identifying YiiFramework"
	strings:
			$baseyii = /class BaseYii/ nocase
	condition:
			$baseyii
}

private rule RoundCubeWebmail
{
	meta:
			custom_description = "Private rule for identifying RoundCube Webmail"
	strings:
			$string = "Roundcube Webmail IMAP Client"
	condition:
			$string
}

private rule phpBB
{
	meta:
			custom_description = "Private rule for identifying phpBB forum software package"
	strings:
			$package = "* @package phpBB3"
	condition:
			$package
}

private rule CactiSuperlinksPlugin
{
	meta:
			custom_description = "Private rule for identifying Cacti Superlinks plugin"
	strings:
			$string = "http://docs.cacti.net/plugin:superlinks"
	condition:
			$string
}


private rule PerlEmailAddressModule
{
	meta:
			custom_description = "Private rule for identifying Perl Email::Address Module"
	strings:
			$string = /package\s+Email::Address;/
	condition:
			$string
}

private rule PerlHTMLScrubberModule
{
	meta:
			custom_description = "Private rule for identifying Perl HTML::Scrubber Module"
	strings:
			$string = /package\s+HTML::Scrubber;/
	condition:
			$string
}

private rule com_aicontactsafe
{
	// @product = "Joomla"
	// @product_root = "../../../"
	// @marker_file = "/administrator/components/com_aicontactsafe/aicontactsafe.xml"
	
	meta:
			custom_description = "Private rule for identifying aicontactsafe component from Joomla CMS"
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
			custom_description = "Private rule for identifying com_theatre component from Joomla CMS"
	strings:
			$name = /<name>iC\s+agenda<\/name>/ nocase
	condition:	
			$name
}
