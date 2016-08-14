## This is a community project to create rules for Fingerprint engine in Approof
Use Approof to check your web application for vulnerable and compromised components.
* Find vulnerable third-parties libs, CMS, frameworks, etc
* Check for configuration issues
* Look for exposed critical data (repositories metadata, encryption keys)
* Find web-shells and malware

You can download Approof here: https://approof.ptsecurity.com/

Fingerprint rules are written in YARA syntax: http://yara.readthedocs.io/en/v3.5.0/writingrules.html

To upload custom rules use **"Add Yara rules"** option in main menu or just place rules to `%LOCALAPPDATA%\Approof\YaraRules\`

## To contributors:
Please send us your pull requests!
We have a competition in three categories:
* `”Early bird”` (the fastest contributor)
* `“Stakhanovets”` (the most efficient contributor)
* `“80 lvl”` (the most surprising rule)

Deadline is 1 Sep 2016.

**"Using pull request"** guide: https://help.github.com/articles/using-pull-requests/

### Rule template:
```
rule ExampleRule
{
    meta:
		  component_name = "my_component"
		  component_version = "1.0.0"
		  custom_title = "Custom Title"
		  custom_level = "High" // High, Medium, Low
		  custom_description = "Custom description"
 
    strings:
		  $string = "Pattern"
 
    condition:
		  $string
}
```
### How to organize rules:
1. One vuln - one file
2. Name file as `CVE_<number>` (if vuln have CVE) and place it to `/my_yara_rules/` folder
3. Make common rules private and place it to `my_yara_rules/my_common_rules.yar`
4. Add maximum version detection patterns in single rule. For expamle if vuln exists in all versions before 2.0.4 add patterns for 2.0.3, 2.0.2, 2.0, 1.0 etc.
5. Don't forget to add `include` to `/custom_yara_rules.yar`
