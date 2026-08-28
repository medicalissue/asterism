# You are running on Asterism

Paste this into your `CLAUDE.md`, `AGENTS.md`, or whatever file your agent
reads first. `ast create --agent` already writes it to
`<workdir>/.asterism/AGENT-SNIPPET.md` inside the box, so you can also point
the agent at that path.

---

This machine is yours. It is a virtual machine on somebody's own hardware, and
you have `ast` for the machine itself:

- **`ast snapshot <name>`** — keep this disk exactly as it is, right now.
  Takes a fraction of a second and costs almost nothing. Run it before
  anything you would not want to have to undo by hand: a schema migration, a
  dependency upgrade, a large refactor, `rm -rf` on anything you did not
  create. You do not need permission and you do not need to ask.
- **`ast rewind`** — the snapshots there are to go back to.
  `ast rewind --to <name>` goes back to one. It restarts this machine, so the
  command you are running now will not return.
- **`ast cost`** — what you have spent on model calls today.
- **`ast fork --n 3`** — three copies of this whole machine, running now, off
  the same disk. Use it when you can see two or three ways to do something and
  trying them is cheaper than arguing about them. `--each "…"` once per fork
  tells each copy what to try. Nobody has to approve it.
- **`ast notify "…"`** — tell the person who owns this machine something.
  Does not wait. Use it when you finish something they will want to know
  about: a pull request opened, a long job done, a deploy out.
- **`ast ask "…"`** — ask them something and wait for the answer, which
  arrives on stdout. Use it when there is a real fork in the road and picking
  wrong is expensive: which of two designs, whether to touch production,
  whether a surprising cost is acceptable. Give them the options in the
  question — `now (A) or tomorrow morning (B)?` — so the answer can be one
  word.

Two things worth knowing:

**`ast ask` blocks, and then stops blocking.** If nobody answers within four
hours it exits non-zero and you carry on. The question stays in their inbox.
So: ask when the answer changes what you would do, and pick a sensible default
in the meantime rather than stopping.

**The credentials you are using are not in this machine.** `$ANTHROPIC_API_KEY`
and friends hold opaque handles; the real values live on the host and are
substituted on the way out to the one service each is bound to. There is
nothing to find, and `ast` in here cannot read them. If you need a credential
you do not have, `ast ask` for it — the person can bind one without ever
putting it in here.
