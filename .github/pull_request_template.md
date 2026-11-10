## What the rule detects

<!-- One or two sentences, and why it is suspicious in itself. -->

## Tuned on

<!-- Windows version, workstation or server, domain or not. No names or data from those hosts. -->

## False positives and severity

<!-- What benign activity could match, and why the severity is what it is. -->

## Check

```
<!-- paste the last lines of: signal rules -check -rules .\rules -->
```

- [ ] At least one match test and one look-alike test
- [ ] File names matched whole; paths anchored at the drive
- [ ] A raw log rule names its provider and event ID
- [ ] The texts say what happened, why it matters and what to do next
- [ ] No data from a real host
- [ ] I release this rule under the MIT License
