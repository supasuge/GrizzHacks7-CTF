FROM ubuntu:20.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

# Install necessary packages with error handling and fallbacks
RUN apt-get update && \
    # Try primary installation
    (apt-get install -y nginx openssh-server python3 sudo curl wget vim net-tools iptables || \
    # If that fails, try updating and installing again
    (apt-get update --fix-missing && apt-get install -y nginx openssh-server python3 sudo curl wget vim net-tools iptables)) && \
    # Clean up to reduce image size
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# TODO: 
# - Enforce strict login policy
# - Enable fail2ban login rate limiting to enforce challenge rules (no bruteforcing/credential stuffing)
# - Add healthcheck script to enable auto-exploitation/retrieval of flags to make sure they are still present and the challenge is solve-able.
# - Start the `start.sh` script using a supervisord.conf file to ensure redundancy of the challenge service/s.

# Configure SSH with error checking - simplified configuration
RUN mkdir -p /var/run/sshd && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Create CTF user with REGULAR bash shell (not restricted)
RUN useradd -m -s /bin/bash ctfuser || echo "User may already exist, continuing" && \
    echo "ctfuser:CTF_password2023!" | chpasswd && \
    echo "ctfuser hard nproc 50" >> /etc/security/limits.conf && \
    echo "ctfuser soft nproc 30" >> /etc/security/limits.conf

RUN mkdir -p /home/ctfuser/bin && \
    ln -s /bin/ls /home/ctfuser/bin/ls && \
    ln -s /bin/cat /home/ctfuser/bin/cat && \
    ln -s /bin/grep /home/ctfuser/bin/grep && \
    ln -s /usr/bin/python3 /home/ctfuser/bin/python3 && \
    ln -s /bin/find /home/ctfuser/bin/find && \
    echo 'export PATH=/home/ctfuser/bin:/usr/bin/python3' > /home/ctfuser/.bashrc && \
    echo 'alias sh="echo restricted"' >> /home/ctfuser/.bashrc && \
    chown -R ctfuser:ctfuser /home/ctfuser/bin && \
    chmod 755 /home/ctfuser/bin

# Copy user flag
COPY user.txt /home/ctfuser/user.txt
RUN chown ctfuser:ctfuser /home/ctfuser/user.txt && \
    chmod 400 /home/ctfuser/user.txt

# Copy root flag
COPY root.txt /root/root.txt
RUN chmod 400 /root/root.txt

# Create the privilege escalation vulnerability
# Making python3 setuid root for privilege escalation
RUN chmod 4755 /usr/bin/python3 || echo "Failed to set SUID bit on python3, check if file exists"
# Double check to make sure SUID bit is set correctly for privilege escalation
RUN ls -la /usr/bin/python3

# Set up nginx with improved security
COPY nginx.conf /etc/nginx/nginx.conf
COPY default /etc/nginx/sites-available/default
RUN ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default && \
    # Add security.conf for better web security
    echo "# Security settings" > /etc/nginx/conf.d/security.conf && \
    echo "server_tokens off;" >> /etc/nginx/conf.d/security.conf && \
    echo "add_header X-Content-Type-Options nosniff;" >> /etc/nginx/conf.d/security.conf && \
    echo "add_header X-Frame-Options SAMEORIGIN;" >> /etc/nginx/conf.d/security.conf && \
    echo "add_header X-XSS-Protection \"1; mode=block\";" >> /etc/nginx/conf.d/security.conf

# Create web directories with error handling
RUN mkdir -p /var/www/html/admin /var/www/html/backup /var/www/html/notes /var/www/html/images /var/www/html/dev /var/www/html/internal && \
    echo "Nothing to see here..." | tee /var/www/html/dev/important.txt /var/www/html/internal/important.txt

# Add website content
COPY index.html /var/www/html/
COPY robots.txt /var/www/html/

# Add challenge files
COPY credentials.txt /var/www/html/admin/
COPY notes.txt /var/www/html/notes/

# Create a simple backup file
RUN echo "This is a backup file with no useful information." > /var/www/html/backup/backup.txt

# Fix permissions
RUN chown -R www-data:www-data /var/www/html && \
    find /var/www/html -type d -exec chmod 755 {} \; && \
    find /var/www/html -type f -exec chmod 644 {} \;

# Expose ports
EXPOSE 80 22

# Create a simple start script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'service ssh start' >> /start.sh && \
    echo 'service nginx start' >> /start.sh && \
    echo 'echo "Container started successfully"' >> /start.sh && \
    echo 'tail -f /dev/null' >> /start.sh && \
    chmod +x /start.sh

CMD ["/start.sh"]
