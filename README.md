# perch-repro-runners

Automated bug reproduction for the [Perch AI](https://www.perchai.app) community Discord.

When someone reports a bug on Windows or macOS in the Perch AI help forum, PerchBot (the
community's support bot) starts the `repro` workflow here. It runs on GitHub's own Windows and
macOS machines and tries the real products, signed out and from empty folders:

- **Perch CLI**: a clean `npm install` of the reported version, `perch --help`, `perch status`
  and, when the report is about editor integrations, the ACP handshake (`perch acp`).
- **Perch Terminal**: downloads the official installer, installs it silently, opens it and takes
  screenshots.

## Privacy

- The workflow gets versions and switches only, never the text of anyone's report.
- Results and screenshots are encrypted for the bot (`bot-public.pem`) before they are uploaded,
  and the uploads are deleted after a day. The workflow logs only name the steps.
- No accounts or keys are used.

Not affiliated with or endorsed by Perch AI.
