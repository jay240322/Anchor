# anchor-skill

An Agent Skill that anchors cybersecurity research findings to a hash-chained evidence
ledger. Every claim in a final report must resolve to a hashed evidence record.

## Install

```bash
npm install -g anchor-evidence-skill
```

## Quickstart

```bash
anchor init
anchor evidence add --tool nmap --observation "22/tcp open ssh"
anchor check
anchor report
anchor stamp
```

## License

MIT
