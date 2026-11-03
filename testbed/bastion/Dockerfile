# Test bed jump host: OpenSSH that only forwards TCP to the target's port 22.
FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd \
    && rm -f /etc/ssh/ssh_host_* && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key \
    && useradd --create-home --shell /usr/sbin/nologin ssh-mcp-jump && usermod -p '*' ssh-mcp-jump
COPY authorized_keys /home/ssh-mcp-jump/.ssh/authorized_keys
COPY 10-jump.conf /etc/ssh/sshd_config.d/10-jump.conf
RUN chown -R ssh-mcp-jump /home/ssh-mcp-jump/.ssh && chmod 0700 /home/ssh-mcp-jump/.ssh \
    && chmod 0600 /home/ssh-mcp-jump/.ssh/authorized_keys && sshd -t
CMD ["/usr/sbin/sshd", "-D", "-e"]
