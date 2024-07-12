FROM python:3.8-alpine
MAINTAINER jgordon005@gmail.com

# Copy in needed artifacts
COPY docker/cron-6hr /etc/cron.d/ip-check-cron
COPY check_my_ip.py /code/check_my_ip.py

# Give execution rights on cron job/script
RUN chmod 0644 /etc/cron.d/ip-check-cron
RUN chmod 0744 /code/check_my_ip.py
# Apply cron job
RUN crontab /etc/cron.d/ip-check-cron

# Run command on container startup (in foreground)
CMD ["crond", "-f"]
