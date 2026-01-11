![project ssti](identification.png)

## Identifying Server-Side Template Injection (SSTI)

SSTI can be identified by injecting simple template expressions and observing how the server processes them. A common first test is an arithmetic expression like *${7*7}* or *{{7*7}}*.
Follow the green lines if the payload worked or follow red line.
If the response evaluates to 49, template execution is likely occurring.

If the expression is rendered as plain text, the input is probably not vulnerable.

Further payloads using template-specific syntax (such as comments {* *}, string operations, or function calls) help narrow down the template engine (e.g., Smarty, Jinja2, Twig).
The image above illustrates a step-by-step decision flow to detect SSTI and identify the underlying template engine.


## Smarty

After confirming that the payload *${7*7}* is evaluated (returns 49), we can attempt template-specific payloads to identify the engine and confirm exploitation.

Smarty supports modifiers, such as upper:
```
{'Hello'|upper}
```
If the output is returned in uppercase (HELLO), this strongly indicates Smarty.

To further confirm and demonstrate impact, we can attempt command execution using the system function:
```
{system("id")}
```
If this returns system user information, it clearly confirms Smarty SSTI with command execution capability.
