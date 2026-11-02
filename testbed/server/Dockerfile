FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      bubblewrap sshfs fuse3 openssh-client util-linux ca-certificates grep gawk findutils jq \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --create-home --home-dir /var/lib/ssh-mcp ssh-mcp \
 && mkdir -p /var/lib/ssh-mcp/data /etc/ssh-mcp && chown ssh-mcp:ssh-mcp /var/lib/ssh-mcp/data && chmod 0700 /var/lib/ssh-mcp/data
COPY ssh-mcp /usr/local/bin/ssh-mcp
# Config and CA key are baked in by up.sh (bind mounts on Docker Desktop do
# not preserve the 0600 ownership the CA loader insists on).
COPY etc/ /etc/ssh-mcp/
RUN chown -R ssh-mcp:ssh-mcp /etc/ssh-mcp && chmod 0600 /etc/ssh-mcp/ca_key /etc/ssh-mcp/audit.key
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
WORKDIR /var/lib/ssh-mcp
# Starts as root only to delegate the cgroup, then drops to ssh-mcp.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
