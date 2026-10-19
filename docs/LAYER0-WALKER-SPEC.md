# Layer-0 bash walker — behavioural specification

Written for whoever implements the walker from scratch. Everything a correct implementation has to
agree about is here; nothing about how the engine it replaces was built is. The acceptance data is
`bash-walker.golden.jsonl` (one input plus the required result per line). `bash-walker-golden.ts`
loads that file and compares one case against a walker result; `bash-walker-golden.test.ts` runs
every line of it and asserts this document's shape rules over the file itself. §15 says which of the
two checks what.

The one question this component answers: **can a trustworthy argument list be produced for every
simple command in this input string?** Yes → return the commands. No → say why. It never returns a
verdict about safety, permission, or intent; the caller decides what a refusal costs. It is not a
sandbox and it is not a policy engine.

## 1. Result shape

For a string of bash, the walker returns one of two results.

**Accepted** — `kind: "simple"` plus `commands`, a list of the simple commands found, in the order
the rules below emit them. Each command carries:

| field | meaning |
| --- | --- |
| `argv` | the command word followed by its arguments, quoting and escapes resolved (§4) |
| `envVars` | leading `NAME=value` prefixes, source order, each with its resolved value (§5) |
| `redirects` | the redirects that belong to this command, source order (§7) |
| `heredocs` | the bodies of the quoted-delimiter heredocs this command owns, source order (§8) |
| `text` | exactly `command.slice(start, end)` — never a reconstruction (§13) |
| `start`, `end` | JS string indices of this command's span in the input (§13) |
| `connector` | the operator written in front of this command (§13) |
| `opaque` | true when some value of this command is only known at run time (§6) |

**Refused** — `kind: "unproven"` plus `reason` (exactly one id from §12), `malformed` (§12), and an
optional `nodeType` naming the construct the walker blames. `nodeType` is a diagnostic for humans
and tooling: no caller may branch on it, and the golden corpus never asserts it.

Rules about the result itself:

1.1 A refusal carries no commands. There is no partial answer.
1.2 `malformed: true` means *the input itself is broken* — an unclosed quote, a control character,
a parse that could not be completed, an input too large to analyse — and the right response is to
ask for a simpler, well-formed command. `malformed: false` means *the input is valid bash that this
walker refuses to reason about*, and the right response is to let the effect model judge it. A
caller switches on the flag, never on the wording of a reason.
1.3 Nothing in the result may be a guess. If the walker cannot tell whether a word is one argument
or three, it refuses.
1.4 Blank input (empty, or only spaces, tabs and newlines) is accepted with an empty command list.

## 2. Order of work

The checks run in this order, and the first refusal wins. The order is observable: an input can be
both badly quoted and full of brace obfuscation, and the caller must get one specific reason.

| step | what is checked | result if it fails |
| --- | --- | --- |
| 1 | input is blank | accepted, no commands |
| 2 | input is longer than the size cap (§10.9) | refused, `input-too-large` |
| 3 | delimiters balance: quotes, backticks, `$(`, `${`, every heredoc delimiter and terminator | refused, one of the `unterminated-*` ids |
| 4 | the text contains only characters this walker accepts (§10.1–§10.2) | refused, `control-character` / `unicode-whitespace` |
| 5 | the text contains no construct whose meaning differs between shells (§10.3–§10.5) | refused, `backslash-whitespace` / `zsh-tilde-bracket` / `zsh-equals-expansion` / `brace-with-quote` |
| 6 | a syntax tree is produced | refused, `parse-error`, `parse-aborted` or `parser-unavailable` |
| 7 | every construct in the tree is one the walker analyses (§3) | refused, a structure or expansion id |
| 8 | every emitted command can be tied back to a span of the input, and every construct that contributes is accounted for | refused, `inventory-mismatch` |
| 9 | the resolved arguments mean what they look like (§11) | refused, a meaning id |
| 10 | every heredoc body in the input is owned by exactly one emitted command | refused, `heredoc-unattributed` |

2.1 Steps 3–5 examine characters, not structure, because they exist to catch places where a
reviewer, a shell and a parser disagree about where a word begins or ends. They are not "cheap
pre-filter then trust the tree": a command that passes them still has to survive steps 7–10.
2.2 The one exception to "run the scans on the input as written" is the heredoc mask (§8.6). It can
only ever *unblock* the step-5 brace scan, and only with a proof (§8.7).
2.3 A refusal at step 7–10 must not be softened by an earlier engine's opinion. The walker's job
ends at the refusal.
2.4 Nothing after step 10 decides anything. The one thing that runs later is **reporting**: a file a
command opens for writing through an option (`sort -o /etc/x`) is appended to that command's
`redirects` once steps 8–10 have vouched for the value the option names, so every reader of "which
files does this command open" reads one list (§7.7). It adds a fact to a command and never a word to
`argv`.

## 3. Structures

### 3.1 Analysed

| input form | what the walker emits |
| --- | --- |
| a plain command | one command |
| `A && B`, `A \|\| B`, `A ; B`, `A & B`, `A<newline>B` | each command in source order, each with the operator in front of it (§13) |
| `A \| B`, `A \|& B` | each stage in source order; a stage is a command like any other |
| `( … )` in statement position | the commands inside, in source order; the parentheses contribute nothing |
| `! cmd` | the wrapped command only; the negation contributes nothing |
| a command with redirects | the command, with the redirects attached to it (§7) |
| a redirect with no command (`> f`) | one command with an empty `argv` and that redirect — it is still a write |
| `[ … ]`, `[[ … ]]` | one command, first argument canonicalised to `[[` (§9) |
| `export` / `local` / `readonly` / `declare` / `typeset` | one command whose first argument is that word, followed by flags and `NAME=value` items as arguments (§5.6) |
| `unset` | one command whose first argument is `unset`, followed by its flags and names |
| a bare `NAME=value` statement | nothing, but the value is remembered for later references (§5.3) |
| a comment | nothing |
| a substitution feeding an accepted argument | the commands inside it, before the command that contains it (§6.2) |

### 3.2 Refused

| input class | reason |
| --- | --- |
| `for` / `select` / `while` / `until` | `loop-body` |
| `if` | `conditional-body` |
| `case` | `case-statement` |
| a function definition, either spelling | `function-definition` |
| `{ …; }` | `brace-group` |
| `(( … ))` in statement position | `arithmetic-command` |
| a subshell used as an argument or as the operand of a wrapper (`time (ls)`) | `subshell-argument` |
| `<(` or `>(` | `process-substitution` |
| anything the walker has no rule for | the closest id in §12 — never a silent pass |

3.3 Loops and conditionals are refused on purpose. Their bodies run a number of times, or not at
all, and the value a loop variable takes is a run-time fact; emitting one copy of the body would
claim an effect set the walker cannot establish. The caller sends these to the effect model. (The
engine this specification replaces walked into loop and conditional bodies; the new walker is
strictly narrower there, and `rej-*` in the golden corpus records that.)

3.4 A construct is refused as a whole. The walker never emits "the parts I understood" of a
construct it does not analyse.

## 4. Words

| written | resolved argument |
| --- | --- |
| `abc` | `abc` |
| `'a b'` | `a b` — nothing is interpreted inside single quotes, not even a backslash |
| `"a b"` | `a b` |
| `"a; b && c"` | `a; b && c` — operators inside quotes never split |
| `a'b'c`, `"a"b`, `a"b"` | one argument `abc`: adjacent quote segments join, they do not split |
| `one\ two` | **refused** (`backslash-whitespace`) — quote the word instead |
| `a\\b` | `a\b` — outside quotes a backslash removes itself from the next character |
| `\{a,b}` | refused (`brace-expansion`) — an escaped brace group is still refused |
| `find … -exec rm {} \;` | the final argument resolves to `;` |
| `*`, `f?.txt`, `[ab]*` | kept exactly as written: the walker performs no file-name matching |
| `~`, `~/x`, `~root` | kept exactly as written in an argument; the caller decides what a tilde means |
| `""` | one empty argument |
| `" "` | one argument holding the run of whitespace inside the quotes |
| `5$`, `cost: $` | a dollar sign followed by nothing expandable is the literal character `$` |
| `"a\nb"` | the two lines with the newline kept, and the backslash kept: inside double quotes `\n` is not an escape |
| `"fix \"bug\""` | `fix "bug"` — inside double quotes a backslash escapes only `$`, backtick, `"` and `\` |

4.1 Expansions the walker resolves: none at run time. It resolves quoting, escapes, and
adjacency; it resolves a variable reference **only** under §5, and the output of an accepted
substitution only as the placeholder of §6.
4.2 Word forms the walker refuses outright, with the id in §12:
`$'…'` (`ansi-c-string`), `$"…"` (`translated-string`), `{a,b}` and `{1..5}` in any position
including a redirect target (`brace-expansion`), `$(( … ))` containing anything other than numeric
literals and operators (`arithmetic-non-literal`), a numeric literal of the form `base#…` with an
expansion after the `#` (`arithmetic-non-literal`), every `${…}` form (`variable-expansion`),
`$@`, `$*` and any positional parameter (`$1`, and `$10` and above are the same class) anywhere
(`variable-expansion`), and any name the walker has no value for (`variable-expansion`).
4.3 `$(( … ))` made only of numeric literals (decimal, hex, octal, `base#digits`) and operators is
accepted and reported as the literal text that was written, not as its value. Bash computes the
value; the walker must not pretend to.
4.4 The walker never produces more than one argument where bash could produce several. If a value
could be split by word splitting or replaced by file-name matching, the input is refused (§5.4).

## 5. Assignments and remembered values

5.1 `NAME=v cmd` — one entry in `envVars`, in source order, and the value is visible to **that
command only**. A later command in the same input may not use it: `A=x && true && echo "$A"` is
refused, because bash would give the second command an empty `A`.
5.2 `NAME=v` alone is inert: no filesystem or process effect, so nothing is emitted for it. It is
still remembered (§5.3).
5.3 A remembered value that is a pure literal is substituted into later references, so the caller
sees the real path: after `D=/tmp/build`, both `rm -rf $D` and `rm -rf "$D"` resolve to
`/tmp/build`. Substituting a placeholder here would hide the target from every later check.
5.4 A literal value may be substituted **bare** only when it cannot be re-split or re-matched: a
value containing a space, tab, newline, `*`, `?`, `[`, or the empty string is refused in bare
position (`variable-expansion`). Inside double quotes any remembered value is safe to substitute,
including one with spaces.
5.5 A value that is not a literal — the output of a substitution, or anything built from a value
that was itself unknown — is remembered as `__TRACKED_VAR__`. Bare use is refused; use inside
double quotes yields the placeholder and marks the command opaque (§6.3).
5.6 `NAME+=v` appends. When both sides are literals the walker remembers the concatenation; when
either side is unknown it remembers `__TRACKED_VAR__`. The `+=` operator is never reported as a
separate argument, and the prefix keeps one entry per assignment as written.
5.7 Assignments that change how the shell reads later text are refused: `IFS` (`ifs-assignment`),
the trace prompt `PS4` (`prompt-variable-assignment`) — a plain assignment is allowed only when the
value uses letters, digits, space and `_:./=[]-`, optionally with `${NAME}` references, and any
append to it is refused — and any value containing a tilde (`tilde-in-assignment`), quoted or not,
because bash may expand it at assignment time.
5.8 A name that bash would not accept as a variable name is not an assignment: `1VAR=value` is a
command word. If the tree hands the walker an assignment whose name is not a letter or underscore
followed by letters, digits and underscores, it refuses (`assignment-name-invalid`).
5.9 The declaring builtins (`declare`, `typeset`, `local`) are refused when a flag changes what an
assignment means: `-n` (`nameref-assignment`, because a reference then resolves to the value of a
name the walker cannot see) and `-i` / `-a` (`subscript-evaluation`, because the right-hand side is
then computed, which can run code hidden in an array subscript). A subscripted name given to any of
them is refused the same way.

### 5.10 Names whose value the walker treats as inert

These always exist, are set by the shell rather than by the command, and are safe to reference
**inside double quotes** only — where the value is one argument. As a bare word the value *is* the
argument, so a bare reference is refused (`variable-expansion`). Inside quotes each resolves to
`__TRACKED_VAR__` and the command becomes opaque.

| name | name | name |
| --- | --- | --- |
| `HOME` | `PWD` | `OLDPWD` |
| `USER` | `LOGNAME` | `SHELL` |
| `PATH` | `HOSTNAME` | `UID` |
| `EUID` | `PPID` | `RANDOM` |
| `SECONDS` | `LINENO` | `TMPDIR` |
| `BASH_VERSION` | `BASHPID` | `SHLVL` |
| `HISTFILE` | `IFS` | |

`IFS` is listed because a reference inside a string is harmless; an *assignment* to it is not
(§5.7). A `${NAME}` spelling of any of these is refused regardless: the brace form may carry a
transformation the walker does not model.

### 5.11 Special names

| inside double quotes | refused everywhere |
| --- | --- |
| `?` (previous exit status), `$` (this shell's id), `!` (last background id), `#` (argument count), `0` (the shell's own name), `-` (current option flags) | `@`, `*`, and every positional parameter — `1` and up, `10` included |

Each accepted special name resolves to `__TRACKED_VAR__`. The rejected ones are refused because in
the shells this runs under they expand to nothing or to caller-supplied text, and a placeholder
would misreport the argument.

## 6. Run-time values: placeholders and `opaque`

6.1 Two placeholder strings appear in the result. They are part of the contract, and they always
mean the same thing: **a value that exists only when the command runs, wearing the shape of a
literal.**
- `__CMDSUB_OUTPUT__` — the output of a substitution the walker accepted and reported separately.
- `__TRACKED_VAR__` — a value the shell controls or the walker remembered as unknown: an inert name
from §5.10, an accepted special name from §5.11, or a remembered variable whose own value was not
a literal.
6.2 When the walker accepts a substitution it emits the commands **inside** it first, then the
command containing it. `X=$(curl -s http://h | sh)` yields the fetch, then the shell stage, then the
assignment-consuming command: nothing may hide inside an argument.
6.3 `opaque` is true for a command when any argument, any `envVars` value, or any redirect target
that is not a descriptor duplicate contains either placeholder **as a substring**. A composite value
such as `out-__CMDSUB_OUTPUT__.txt` is opaque like a bare one.
6.4 A command whose argument list is opaque has not been proven literal. The caller is expected to
stop treating its arguments as facts; the walker's obligation is only to flag it.
6.5 An argument that consists **entirely** of a run-time value is refused before a placeholder can
be produced for it, because the caller would then be handed a value-shaped hole where a path
should be: a double-quoted substitution and nothing else, or a double-quoted reference to an
inert or unknown-value name, is refused (`command-substitution`, `variable-expansion`,
`runtime-only-argument`). The same value embedded in a longer string is accepted
(`"sha: $(git rev-parse HEAD)"` → one argument `sha: __CMDSUB_OUTPUT__`, opaque).
6.6 One substitution form has a known, fixed answer and is therefore *not* a placeholder: a
substitution whose entire content is `cat` with nothing but a quoted-delimiter heredoc. Its body is
literal data and becomes the argument's value exactly as the substitution would yield it (what `cat`
prints, with the trailing newlines a substitution drops; `<<-` strips leading tabs per line, §8.2), so a path written in
a one-line body stays visible to the caller and a multi-line body arrives the way the same program
would if it had been written as a quoted argument — a `bash -c "$(cat <<'X' … X)"` must show the
caller the script it runs, never an empty string that reads as an interactive shell. The body still
has to pass the meaning checks of §11 — it is the argument. Any deviation (another verb, another
argument to `cat`, an unquoted delimiter) is refused as an ordinary substitution.
6.7 Backtick substitution is a substitution: the same rules apply, including the refusal of a bare
one.

## 7. Redirects

| operator | meaning | reported |
| --- | --- | --- |
| `>` | truncate/write | `op: ">"`, `target` |
| `>>` | append | `op: ">>"`, `target` |
| `<` | read from file | `op: "<"`, `target` |
| `<<<` | here-string: the content is standard input | **not reported** — it is data, not a path; the content is still validated like an argument, and a substitution or unresolved reference in it refuses the command |
| `>&` | duplicate the output descriptor, or write when the target is a file | `op: ">&"`; `fdDup: true` only when the target is digits only |
| `<&` | duplicate the input descriptor, or read when the target is a file | `op: "<&"`, same duplicate rule |
| `>|` | write, overriding no-clobber | `op: ">|"`, `target` |
| `&>` | write, both streams | `op: "&>"`, `target` |
| `&>>` | append, both streams | `op: "&>>"`, `target` |
| `<>` | open for reading and writing | **refused**, `redirect-unsupported` — the effect is both a read and a write and the caller cannot be given one of those |

7.1 An explicit descriptor number in front of an operator (`2> err.txt`, `0< in.txt`) is reported in
`fd`; it is absent when the input did not write one.
7.2 `2>&1` is a descriptor duplicate, not a file: `op: ">&"`, `target: "1"`, `fd: 2`, `fdDup: true`.
`>& /dev/null` is a write: same operator, `fdDup: false`.
7.3 A target is resolved like an argument: quotes removed, escapes resolved, adjacent quoted and
bare parts joined, no file-name matching performed, a brace group in a target refused, a
substitution in a target refused, an unresolved reference in a target refused. A remembered literal
resolves here exactly as it does in an argument (`D=/tmp && echo ok > "$D/out.txt"` → target
`/tmp/out.txt`).
7.4 Redirects attach to the command whose streams they redirect: to that command when it is a plain
command, and to the **last** command of a pipeline or list written inside the same redirect scope.
Multiple redirects on one command are reported in source order.
7.5 A redirect written with no command at all is still emitted (§3.1) — truncating a file is a
consequence even when nothing is printed.
7.6 A placeholder in a target makes the command opaque; a descriptor duplicate target never does,
because `1` and `2` are descriptors, not paths.
7.7 A write named by an **option** rather than by an operator arrives on this same channel.
`sort -o /etc/x` truncates `/etc/x` exactly as `sort > /etc/x` does, and no node in the tree says so:
the flag is an ordinary word and its operand an ordinary argument, so a reader that only knows
redirect nodes calls the command read-only. The walker therefore appends `{ op: ">", target: "/etc/x" }`
to the command that named it — `>>` where the tool's option appends — after the checks have resolved
the operand, so a placeholder target needs no special case (the command is already `opaque`, §6.3).
Which options mean this is a short reviewed table, `OUTPUT_FLAG_WRITES` in
`bash-walker-meaning.ts`: `sort -o` (alone, fused, or in a cluster), `uniq --output`, `patch -o`,
`tee -o`/`--output`, and `git --output` only when the invocation also names one of `diff`, `show`,
`log` — because that is the option family `git-diff(1)` documents and no other git verb takes it.
Words after a bare `--` are operands, not flag operands, so an `--output` written there is a filename
and reports nothing; a tool that is not in the table reports nothing either, which is what keeps
`ssh -o BatchMode=yes` and `grep -o` from being read as writes. What the target then costs or buys is
a policy question and belongs to the gate specification (`docs/CLASSIFIER-SPEC.md` §2.7); the
walker's obligation ends at reporting it.

## 8. Here-documents

8.1 Only a **quoted** delimiter makes a body inert data: `<<'E'`, `<<"E"`, `<<\E`. A body with an
unquoted delimiter is expanded by the shell — parameter, command and arithmetic expansion all run
inside it — so the walker refuses the whole command (`heredoc-unquoted-delimiter`). It must not try
to rescue the unquoted form by looking inside the body: the parser does not report every expansion
that occurs there.
8.2 `<<-` behaves exactly like `<<` for this decision: what matters is whether the delimiter is
quoted. A tab-stripping heredoc with a quoted delimiter is accepted, and the body is handed over
verbatim, **leading tabs included** — removing them is the shell's job, and a caller that reads the
body as a program must see what was written.
8.3 A body is attached to the command that owns the redirect, in source order, and several bodies on
one command keep their source order. A body never becomes part of an argument, and never appears in
`text`: the owning command's span ends at its last argument, before the redirect (§13).
8.4 `interpreter - <<'PY'` must produce `argv` `["interpreter", "-"]`. The grammar loses a lone `-`
when a heredoc redirect follows it; recovering it is required behaviour, not a nicety — the dash is
how the interpreter is told to read its program from standard input, and dropping it would report
`python3` where bash runs `python3 -`. `python3 - x <<'PY'` keeps `-` and `x` in order.
8.5 A file descriptor in front of the heredoc operator (`cat 3<<'E'`) is accepted, and the number is
not reported: the body is attached and the descriptor is not a redirect.
8.6 **The mask.** The step-5 brace scan (§10.5) reads text, and a quoted body full of JSON, YAML or
Python contains braces next to quotes. So that scan may be re-run against a copy of the input in
which the *body* of every quoted-delimiter heredoc is replaced by spaces of the same length,
newlines kept. Nothing else about the input changes, and no other scan, check or reported value ever
sees the masked copy.
8.7 The mask is all-or-nothing and proof-carrying: if the input has even one heredoc with an
unquoted delimiter, or a heredoc redirect the walker cannot account for, no masking happens at all.
After masking, the masked input must parse to a structure with the same constructs at the same
positions and the same count as the original; if that does not hold exactly, the mask is thrown away
and the original refusal stands.
8.8 What the walker returns always comes from the unmasked input: a body handed to the caller is the
text that was written, never the blank. A caller that feeds a body to an interpreter must not be
handed an empty script in place of a destructive one.
8.9 A heredoc operator with no matching terminator line, or a delimiter whose quote never closes, is
malformed (`unterminated-heredoc`, `unterminated-heredoc-delimiter`). A body that cannot be attached
to a command — including a pipeline written on the delimiter line after the body begins — is refused
(`heredoc-unattributed`, not malformed: the input is valid bash, the walker just cannot say who owns
it).

## 9. Test commands

9.1 Both spellings are analysed, and the first argument is `[[` in both cases; the closing bracket
is dropped. `test …` is a plain command and keeps its own first argument.
9.2 Operators and operands are flattened into `argv` in source order: `[[ -f a && -d b ]]` → `[[`,
`-f`, `a`, `&&`, `-d`, `b`. Parentheses and negation inside the test are reported as written.
9.3 The right-hand side of a pattern match is kept as written; it is pattern text, not code.
9.4 Operands are resolved exactly like arguments (§4–§5): a safe name inside quotes resolves and
makes the command opaque, a reference that resolves to nothing but a run-time value is refused, and
a brace expansion or substitution in an operand is refused.
9.5 An arithmetic comparison inside a bracketed test makes both of its operands numeric contexts: a
name containing an array subscript on either side is refused (`subscript-evaluation`), because the
shell computes the subscript and a substitution hidden inside it runs.

## 10. Rejections decided from the text

| id | input class | malformed |
| --- | --- | --- |
| `unterminated-quote` | a single or double quote with no closing partner, including one opened inside a heredoc delimiter | true |
| `unterminated-backtick` | a backtick with no closing partner | true |
| `unterminated-substitution` | `$(` or `${` that is never closed | true |
| `unterminated-heredoc` | a heredoc operator whose terminator line never appears | true |
| `unterminated-heredoc-delimiter` | the delimiter after `<<` opens a quote that never closes | true |
| `control-character` | any of NUL through backspace, vertical tab through unit separator, delete, or carriage return, anywhere in the input | true |
| `unicode-whitespace` | a character that renders as space, or as nothing, in a review but is an ordinary word character to the shell: no-break space, ogham space, the ranges U+2000–U+200B, line and paragraph separator, narrow no-break space, medium mathematical space, ideographic space, byte-order mark | true |
| `parse-error` | the parser could not build a tree at all, including a stray operator, an unbalanced parenthesis, or a separator with no command after it | true |
| `parse-aborted` | the parser stopped under a time or node budget | true |
| `input-too-large` | the input is longer than the cap (§10.9) | true |
| `backslash-whitespace` | a backslash immediately before a space or tab, or a backslash-newline that joins two characters that were inside one word | false |
| `zsh-tilde-bracket` | `~[` anywhere | false |
| `zsh-equals-expansion` | a word that begins with `=` followed by a name character | false |
| `brace-with-quote` | a `{` … quote sequence that brace expansion cannot be ruled out for (§10.5) | false |
| `parser-unavailable` | no parser at all in this process | false |

10.1 A backslash-newline that only separates commands (`true && \` then the next line) is **not** in
the refused class: there is no word to join and every reader agrees where the command starts.
10.2 Carriage return belongs with the control characters: some readers treat it as a separator, the
shell treats it as part of the word.
10.3 `~[` and a leading `=` are refused because a zsh user's shell would run something else there;
the walker cannot know which shell is configured.
10.4 `VAR=1` and `--flag=x` have `=` mid-word and are therefore not the leading-`=` class.
10.5 The brace-with-quote class exists for constructions that use quotes inside a brace group to hide
what the group expands to. It is decided on text with the braces that sit inside single or double
quotes blanked out — a brace inside quotes cannot start a brace group — so a JSON payload passed with
`-d '{"k":"v"}'` is not this class. Braces in an inert here-doc body are handled by the mask (§8.6).
An escaped brace group (`\{a,b}`) stays refused even though the shell would take it literally: the
distinction is easy to get wrong and single quotes do the same job.
10.6 Whichever text scan fires must name its own class; a refusal may not be reported as a generic
"could not parse", because `malformed` is derived from the class and a rewrite is only useful if the
class is real.
10.7 A tree that contains a node the walker cannot complete is `parse-error` with `malformed: true`:
the input is not a command, so the agent should write a simpler one.
10.8 The size cap and the parser budgets are the two places where refusing has a cost measured in
work skipped rather than risk avoided. Both are still refusals, and both are `malformed` — the fix is
a shorter command.
10.9 The cap is **10 000 characters** of input — one constant, `MAX_COMMAND_CHARS` in
`bash-parser.ts`, imported by every place that enforces it, so there is no second number to drift.
An input over the cap is never partially analysed. The parser's own budgets are separate and produce
`parse-aborted` (§12): `MAX_TREE_NODES` 50 000, checked after the parse, and `PARSE_TIMEOUT_MS`
300 ms for the whole call, split over `PARSE_ATTEMPTS` 2.

## 11. Refusals decided from the resolved arguments

These run only after a clean argument list exists: the input parsed, the words resolved, and the
result still must not be trusted.

| id | input class |
| --- | --- |
| `evaluates-arguments-as-code` | a command whose arguments the shell runs as shell code: `eval`, `source`, `.`, `exec`, `command` (only reporting options `-v`/`-V` lift it), `builtin`, `fc` (a reporting option `-l`/`-n`/`-r`/`-t` lifts it; bare `fc` re-executes and is refused), `trap`, `enable`, `hash`, `mapfile`/`readarray` with a callback (`-C`), `bind`, `complete`, `compgen` with an executing or expanding option (`-C`/`-F`), `alias`, `let`, `coproc`, and the option-disabling prefixes `noglob` and `nocorrect` |
| `zsh-module-builtin` | a name that is not a program on disk but an internal of another shell, reachable only through a module loader: `zmodload`, `emulate`, `sysopen`, `sysread`, `syswrite`, `sysseek`, `zpty`, `ztcp`, `zsocket`, and the `zf_` file-operations family |
| `wrapper-not-analysable` | a scheduling or environment wrapper whose arguments the walker cannot walk past: `timeout` with a flag it does not know or a duration it cannot read, `env` with a flag that splits a string into arguments or changes the working directory or path, `stdbuf` with a long option that is not of the `name=value` form, `nice` whose first argument is an expansion. A wrapper whose form is known is peeled so the meaning checks see the wrapped command; a wrapper that cannot be peeled is refused rather than judged as itself. The peelable set is `env`, `nice`, `stdbuf`, `timeout`, `nohup`, `time` — `WRAPPERS` in `bash-walker-meaning.ts` — and stacked wrappers are peeled repeatedly |
| `subscript-evaluation` | a builtin that re-reads a name operand and computes an array subscript in it, so a substitution hidden inside single quotes runs: `-v`/`-R` on the test builtins, `-v` on `printf`, `-a`/`-A` on `read`, `-v` on `unset`, `-p` on `wait`, the `-i`/`-a` declaring flags (§5.9), a subscripted bare name given to `read` or `unset`, and an arithmetic-comparison operand (`-eq`, `-ne`, `-lt`, `-le`, `-gt`, `-ge`) inside a bracketed test (§9.5). A prompt or other data-taking operand is not a name: `read -p '[dir] ' v` is fine |
| `nameref-assignment` | §5.9 |
| `proc-environ-read` | an argument or a redirect target naming another process's environment file under `/proc/…` — path segments are resolved in the kernel, so anything that walks to `environ` counts, including through `..` and through an escaped spelling |
| `jq-system-call` | a `jq` program containing its code-executing builtin |
| `jq-file-flag` | a `jq` invocation with a flag that loads a program, a raw file, a slurped file or a library path, each of which either runs code or pulls an arbitrary file into the filter |
| `empty-command-name` | a resolved first argument that is empty: the shell drops an empty expansion at command position and runs what follows, so the argument list does not describe the command |
| `command-name-not-a-literal` | a first argument that contains a placeholder: which program runs is a run-time fact |
| `incomplete-command-fragment` | a first argument that begins with `-`, `|` or `&`: what was emitted is a piece of a command, not one |
| `keyword-as-command-name` | a shell reserved word in first position: only a mis-parse can put one there, and a keyword can never be a program name |
| `hidden-comment-in-argument` | a newline followed by optional blanks and `#` inside an argument, an environment value, or a redirect target: anything that re-reads the source line by line stops seeing the rest of the argument at that point |

11.1 `sudo` and other privilege wrappers are **not** this walker's business: it reports
`["sudo", …]` and the caller decides. Same for `xargs`, whose argument command the caller judges.
11.2 A wrapper is peeled only for these checks, never in the reported argument list — the caller must
see what was written.
11.3 Checks that read a value must read the resolved value. An escaped spelling (`\environ`), a
quoted name, or a fused flag (`-vNAME`) each hides the same meaning from a check that reads the raw
source.
11.4 These refusals are never malformed. The input is well-formed; the walker is declining to reason
about it.

## 12. Reason vocabulary

The complete set of ids a refusal may carry. A new id is added only with a golden case that needs it.
This table is not a description of somebody's list; it *is* the list, kept in three places that have to
agree item for item: the `Reason` union in `bash-walker.ts`, which is what `refuse()` accepts; the
`MALFORMED_CLASSES` set beside it, which fills in `malformed` for every refusal; and this table. The
agreement is only partly machine-checked. `refuse()` derives `malformed` from that set and the corpus
asserts `malformed` for every case it carries, so the suite fails on any id whose column here disagrees
with the set — for every id the corpus has a case for. Nothing machine-checks this table against the
union, which is why adding an id is a change to all three and not to one.

| reason | malformed | refused because |
| --- | --- | --- |
| `unterminated-quote` | true | a quote never closes |
| `unterminated-backtick` | true | a backtick substitution never closes |
| `unterminated-substitution` | true | `$(` or `${` never closes |
| `unterminated-heredoc` | true | no terminator line for a heredoc |
| `unterminated-heredoc-delimiter` | true | the heredoc delimiter's quote never closes |
| `control-character` | true | invisible control characters move word boundaries |
| `unicode-whitespace` | true | invisible space-like characters are word characters |
| `parse-error` | true | no complete tree exists |
| `parse-aborted` | true | the parser gave up under a budget |
| `input-too-large` | true | the input exceeds the size cap |
| `parser-unavailable` | false | no parser in this process |
| `backslash-whitespace` | false | escaped whitespace, where readers disagree |
| `zsh-tilde-bracket` | false | another shell's dynamic directory syntax |
| `zsh-equals-expansion` | false | another shell's path lookup at word start |
| `brace-with-quote` | false | brace-group obfuscation involving quotes |
| `brace-expansion` | false | one written word becomes several arguments |
| `ansi-c-string` | false | escape-interpolated string form |
| `translated-string` | false | locale-translation string form |
| `arithmetic-non-literal` | false | arithmetic that references a name or runs a substitution |
| `command-substitution` | false | an argument's value, or part of it, is produced by running something |
| `process-substitution` | false | a file name is created at run time by running something |
| `variable-expansion` | false | a reference the walker has no literal value for |
| `runtime-only-argument` | false | the whole argument is a value known only at run time |
| `loop-body` | false | a loop: iteration count and loop value are run-time facts |
| `conditional-body` | false | a conditional: whether the body runs is a run-time fact |
| `case-statement` | false | which branch runs is a run-time fact |
| `function-definition` | false | a definition whose calls are elsewhere |
| `brace-group` | false | a grouped compound command |
| `arithmetic-command` | false | arithmetic evaluated as a statement |
| `subshell-argument` | false | a subshell used where an argument belongs |
| `inventory-mismatch` | false | the emitted commands cannot be tied back to the input's spans |
| `heredoc-unattributed` | false | a body the walker cannot give an owner |
| `heredoc-unquoted-delimiter` | false | the body is expanded by the shell |
| `redirect-unsupported` | false | a redirect form whose effect the contract cannot express |
| `ifs-assignment` | false | the separator that decides how values split |
| `prompt-variable-assignment` | false | the trace prompt runs as code |
| `tilde-in-assignment` | false | the shell may expand the tilde at assignment time |
| `assignment-name-invalid` | false | not a name the shell accepts, so not an assignment |
| `nameref-assignment` | false | a reference that resolves to the value of another name |
| `subscript-evaluation` | false | a name operand the shell computes, running what hides in the subscript |
| `evaluates-arguments-as-code` | false | the shell runs the arguments |
| `zsh-module-builtin` | false | an internal of another shell |
| `wrapper-not-analysable` | false | a wrapper that cannot be peeled, so the real command is unseen |
| `proc-environ-read` | false | reads another process's environment |
| `jq-system-call` | false | the filter runs commands |
| `jq-file-flag` | false | the filter is loaded from a file or library path |
| `empty-command-name` | false | the shell drops the empty word and shifts the rest |
| `command-name-not-a-literal` | false | which program runs is decided at run time |
| `incomplete-command-fragment` | false | what was emitted is not a whole command |
| `keyword-as-command-name` | false | only a mis-parse puts a keyword there |
| `hidden-comment-in-argument` | false | a hidden comment hides the tail of a value |

12.1 One refusal, one reason. When several apply, the earliest step of §2 that fires supplies it.
12.2 Reasons are stable ids, not messages. Wording for a human is composed by the caller from the id
and, when useful, `nodeType`.
12.3 Four ids have no golden case, because no input can produce them: `parse-aborted` and
`parser-unavailable` describe the process rather than the command; `assignment-name-invalid` and
`command-name-not-a-literal` are reachable only if some earlier rule of this document is broken. They
stay in the vocabulary because a caller has to handle them, and `bash-walker-golden.test.ts` asserts
that the corpus carries no case for exactly these four — an id with no case is the expected state
there, not a gap. `inventory-mismatch` was in this list until a defect of the grammar
in use (tree-sitter-bash 0.25.1) made it reachable from valid input: a pipeline of three or more stages
followed by newline-separated commands whose last carries a redirect is parsed as one pipeline whose
last stage holds the lines below as words. The walker refuses that command under §2 step 8 because its
words are tied to a span that crosses statement boundaries (§13.6); `malformed` is false, the input is
valid bash. Golden case `im-newline-joined`.

## 13. Spans, text, connector

13.1 `start` and `end` are **JS string indices** into the input exactly as the caller holds it, so
that `text` is the ordinary substring of the input and any later slicing lines up. A character
outside the Basic Multilingual Plane counts as the two units the language gives it, and a
multi-byte character counts as the units the caller's string gives it. Offsets that a parser reports
in bytes must be converted, exactly, not searched for.
13.2 `text` is `input.slice(start, end)` — the source, with its original quoting, its original
`$` references, its original line continuations. It is never rebuilt from `argv`. Consequence: `text`
is for display and attribution only; anything that decides must read `argv`.
13.3 A command's span covers the command word, its arguments and its own redirects. It excludes a
heredoc body, and excludes the parentheses of a subshell or the operator in front of it.
13.4 `connector` is the operator written in front of this command: `""` for the first command of the
input and for anything whose predecessor was separated by nothing more than a newline inside the same
heredoc-delimited run, `";"`, `"&&"`, `"||"`, `"|"`, `"|&"`, `"&"`, or `"\n"` when the separator was a
bare newline. It describes how this command relates to the one before it, and nothing in a verdict
may depend on it.
13.5 A command emitted from inside a substitution is reported **before** the command that contains it,
and its span points at the inner source — so spans are not required to be sorted, and one span may sit
inside another. Where a command comes from inside a substitution, the connector it reports is the one
that applied inside it.
13.6 Every emitted command's span must contain the words it reports. If the walker cannot show that,
it refuses with `inventory-mismatch` rather than reporting a command it cannot point at. This is the
invariant that catches a walker disagreeing with its own tree about how many commands there are, so no
valid input should ever reach it. The places where a command is easiest to lose or invent — `unset`, a
redirect with no command word, a substitution feeding an accepted argument, a statement-level
assignment — are in the corpus as **accepted** cases for exactly that reason: the required answer
there is a command, not a refusal.

## 14. Invariants

14.1 Fail closed. Every path that is not a proof ends in a refusal. There is no branch that returns
"no commands" because the walker gave up, and no branch that returns a partially resolved command list.
14.2 Refusing is cheap; pretending is not. A refusal costs one model call or one prompt. A wrong
`argv` costs a decision made on invented facts, which is why placeholder-for-a-path and
drop-the-body behaviours are called out explicitly above.
14.3 The walker never widens: it does not resolve a value it was not told, does not strip a wrapper
it cannot locate, and does not analyse the inside of a construct it has refused for other reasons.
14.4 Deterministic: the same input string always produces the same result, with no clock, no
filesystem and no environment reads.
14.5 The walker holds no policy. It does not know what a project directory is, which paths are
secret, or which verbs delete. It says only what a command is made of, and whether it could tell.

## 15. The golden corpus

`bash-walker.golden.jsonl` — one JSON object per line: `id`, `command`, `expect` (the required result
in the shape of §1; for a refusal, `kind`, `reason`, `malformed`), and `note` on the lines where the
required result deliberately departs from the engine this walker replaces, saying which and why — the
notes name that engine, nothing in this document does. `nodeType` is never asserted.

Three things read this file, and each answers a different question:

- **`loadGolden()` (`bash-walker-golden.ts`)** — shape. It reads the file in line order and throws on
  any line that is not a case, naming the line, so a half-written corpus fails loudly at load instead
  of quietly shortening the suite.
- **`compareCase()` (same file)** — one case against one walker result. It is deliberately stricter
  than the corpus needs: for an accepted case every field of every command must deep-equal `expect` —
  `argv`, `envVars`, `redirects`, `heredocs`, `text`, `start`, `end`, `connector`, `opaque` — in the
  order they were emitted; for a refusal, `kind`, `reason` and `malformed`. It answers with the first
  difference it found, in words, because "case `hd-dash` failed" is not actionable.
- **`bash-walker-golden.test.ts`** — the integration proof: every case, no subset, no deferral list,
  plus the corpus's own rules (ids unique; `inventory-mismatch` present, §12.3; the four ids §12.3
  calls unreachable absent).

Each walker part's own test file runs a subset of the same corpus, selected by id prefix with
`selectById` — `bash-walker.test.ts` (`sep-`, `sub-`, `rej-`, `span-`, `test-`, `word-`, `red-`),
`bash-walker-values.test.ts` (`assign-`, `cs-`, `decl-`, `exp-`, `unset-`),
`bash-walker-heredoc.test.ts` (`hd-`, `mal-`, `pre-`), `bash-walker-meaning.test.ts` (`sem-` plus
named cases) and `bash-walker-remember.test.ts` (`mem-`) — so a failure names the module that owns the
construct. The prefix routes the case and nothing else: the required result is the same object whoever
runs it.

One exception to "the corpus is the contract", and it belongs to §12.3 rather than to the command:
`parse-aborted` and `parser-unavailable` describe the machine, and on a loaded machine the same input
can refuse `parse-aborted` on one run and accept on the next, because the parser's budget is a
wall-clock. `parseWithEnvironmentRetry` therefore re-runs a case whose verdict carries one of those
two ids, and the retried verdict is the one asserted. That is not a tolerance: an input that really
cannot be parsed refuses on every attempt, and no other id is ever retried.
