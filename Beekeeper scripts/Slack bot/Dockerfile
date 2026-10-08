#small python image that just runs the alerter loop
FROM python:3.13-slim
RUN pip install --no-cache-dir requests
WORKDIR /app
COPY Slack_alerter.py .
#-u = unbuffered, so prints show up in `docker logs` straight away
CMD ["python", "-u", "Slack_alerter.py"]
