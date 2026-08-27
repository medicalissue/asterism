# Asterism agent image: OpenAI Codex.
#
# Build from the `images/` directory, which is the context that holds the two
# scripts every agent image shares:
#
#   docker build -f agent-codex/Dockerfile -t agent-codex:dev .
#
# What is in here and why:
#
#   node LTS      the agent CLI is published on npm and nowhere else
#   git           the point of a workspace
#   tmux          the session `ast attach` reattaches to
#   openssh-server how `ast attach` gets a tty into the guest
#   e2fsprogs     the guest formats its own data volume the first time
#   util-linux    blkid, so it only formats it the first time
#   curl, ca-certificates  what the agent's own installer and the CLI expect
#
# What is deliberately NOT in here: a credential. The agent authenticates
# through an opaque handle Asterism's egress door swaps for the real value on
# its way out, so this image is safe to publish and safe to share between
# instances.
#
# The Asterism guest agent is not baked in either: the host injects it into
# pid 1's generated init at boot, so an agent image needs no Asterism build
# artifact in it and stays a plain OCI image anyone can run.
FROM node:22-bookworm-slim

ARG CODEX_VERSION=latest

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      e2fsprogs \
      git \
      less \
      openssh-server \
      procps \
      tmux \
      util-linux \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g "@openai/codex@${CODEX_VERSION}" \
 && npm cache clean --force

# One key, no passwords, and no PAM: the only way in is the host guest key
# that `ast create --agent` writes through the authenticated control channel.
#
# root's password field is left exactly as the base image ships it — `*`,
# meaning "no password was ever set". It is deliberately NOT locked with
# `passwd -l`: that writes a `!` prefix, and OpenSSH with `UsePAM no` reads
# that prefix as a locked account and refuses the connection *before* it looks
# at any key. Locking an account that has no password to lock would buy
# nothing and cost every `ast attach`.
RUN printf '%s\n' \
      'PermitRootLogin prohibit-password' \
      'PasswordAuthentication no' \
      'KbdInteractiveAuthentication no' \
      'UsePAM no' \
      'PrintMotd no' \
      'AcceptEnv LANG LC_*' \
      > /etc/ssh/sshd_config.d/10-asterism.conf \
 && grep -q '^root:\*' /etc/shadow

COPY agent-entrypoint.sh /usr/local/sbin/asterism-agent-entrypoint
COPY agent-env.sh /usr/local/sbin/asterism-agent-env
RUN chmod 0755 /usr/local/sbin/asterism-agent-entrypoint /usr/local/sbin/asterism-agent-env

ENV AST_AGENT_WORKDIR=/work \
    TERM=xterm-256color
WORKDIR /work

ENTRYPOINT ["/usr/local/sbin/asterism-agent-entrypoint"]
