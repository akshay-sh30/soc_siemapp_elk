FROM ubuntu:latest

# Install Cron & Python
RUN apt-get update && apt-get -y install cron python3-pip python3-dev && pip3 install --upgrade pip

# Prepare Cron
RUN mkdir -p /etc/cron.d
RUN touch /var/log/cron.log

# Prepare soc_siemapp_elk
RUN mkdir -p /etc/soc_siemapp_elk
RUN touch /var/log/soc_siemapp_elk
COPY run_usecase.sh /usr/bin
RUN chmod +x /usr/bin/run_usecase.sh

# Install soc_siemapp_elk
RUN mkdir -p /tmp/soc_siemapp_elk
COPY soc_siemapp_elk /tmp/soc_siemapp_elk/soc_siemapp_elk
COPY setup.py /tmp/soc_siemapp_elk/setup.py

RUN ls /tmp/soc_siemapp_elk

RUN pip3 install /tmp/soc_siemapp_elk
RUN rm -rf /tmp/soc_siemapp_elk

# Run cron
CMD rsyslogd && crontab -u root /etc/cron.d/usecases && cron -f -l 1
