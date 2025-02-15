Yara Notes/CheatSheet

To dissect PE using sample command:

import "pe"
rule pe_mod { condition: pe.is_pe }

Yara will dissect and provide a log of information, including the masquerading.

A dope of a YARA documentation: https://yara.readthedocs.io/en/stable/modules/pe.html

Command to run YARA against a sample is:

$ yara example.yar sample.exe

### PE Characteristics

- **pe.characteristics**
    - PE file header information
    - For example, to detect if a file is a DLL: `pe.characteristics & pe.DLL`

- **pe.exports("")**
    - Used to see if an export function name exists in the file
    - For example: `pe.exports("CPlApplet")`

- **pe.machine**
    - Check CPU architecture
    - For example: `pe.machine == pe.MACHINE_AMD64`

- **pe.locale()**
    - Can contain language information
    - For example: `pe.locale(0x0011)` <- Japanese

- **pe.language()**
    - Can contain language information
    - For example: `pe.language(0x0A)` <- Spanish

- **pe.sections[].name**
    - Used to see if a section with a name exists at the specific array
    - For example: `pe.sections[0].name == ".data"`
    - You may want to think about this one when you see deviations from the typical PE sections

- **pe.number_of_sections**
    - Used to check the number of PE sections within a file
    - For example: `pe.number_of_sections == 3`


Usageof Global rule and private rule

global rule example { condition: pe.is_pe }

private rule example2 { string: $s1 = "mscoree" condition: $s1}

Running Yara generator

$ python3 yarGen.py -m <path_to_directory> --excludegood -o <path_to_output>

NOTE : The "--excludegood" here removes strings from the rule that are commonly found in typical software. This is done in an effort to prevent false positives.