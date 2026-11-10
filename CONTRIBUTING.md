# Contributing a rule

Thank you for sharing a rule. This page says what a rule needs and how it is reviewed.
The full format is in the documentation:
[How a rule works](https://intrusion.academy/signal/doc/latest/rules-how-they-work),
[Rule syntax](https://intrusion.academy/signal/doc/latest/rules-syntax),
[Testing and tuning](https://intrusion.academy/signal/doc/latest/rules-testing).

## Before you open a pull request

1. **One concern per pull request.** One rule, or a few rules about one topic.
2. **Put it in `rules/`**, in a file named after the module: `executions-<what-it-finds>.json`.
3. **Give it a new `id`:** the module's prefix and a name (`EXEC-NETSH-HELPER-ADDED`). `signal rules` lists the ids already taken.
4. **Write the tests:** at least one record it must match and one look-alike it must not (`notrclone.exe`, a `-ExecutionPolicy` switch, "Temp" in a program's folder name).
5. **Run the check** with a current Signal. It must say `none failed`:

   ```
   signal rules -check -rules .\rules
   ```

6. **Tune it** on clean hosts. Add every false positive you meet as a look-alike test, or narrow the rule.

## In the pull request

Say:

- what the rule detects and why that is suspicious in itself;
- which hosts it was tuned on (Windows version, workstation or server, domain or not); no names or data from those hosts;
- its known false positives, and why its severity is what it is;
- the output of `signal rules -check`.

## The review checklist

Every rule is reviewed against this list before it is merged. The maintainers run the check themselves on a current Signal.

| Check | Why |
|---|---|
| The check passes, with a look-alike test | The fidelity contract: a rule without a look-alike does not run. |
| File names matched whole; paths anchored at the drive | Not fooled by a chosen name (`\cmd.exe`, not `cmd.exe`) or path. |
| A raw log rule names its provider and event ID | One ID means different things from different providers. |
| The severity follows the criteria; a state is `medium` at most | Severities mean the same in every rule. `critical` only when no legitimate activity is known to match. |
| The texts say what happened, why it matters and what to do next | An analyst can act on the signal alone. |
| The rule is defensive: it detects, it never explains how to attack | The library is for defenders. |
| Tags are only what the evidence shows happened | A capability is not its use. |
| No data from a real host | No host names, user names, IP addresses or paths that identify a person or an organisation. |

A reviewer may ask for changes, rename the file, or adjust the wording to match the other rules.
A rule may be closed if it duplicates a built-in rule, fires on common benign activity, or cannot be tested.

## Naming attack tools

A rule may name an attack tool or its command syntax where the detection needs it. Prefer describing the behaviour
when the rule reads as well that way. Keep the `.json` as the source in this repository; users pack it on their side
(`signal rules -pack`) if their antivirus quarantines plain files.

## License

By opening a pull request you agree that your contribution is released under the [MIT License](LICENSE).
Please also follow the [Code of Conduct](CODE_OF_CONDUCT.md).
