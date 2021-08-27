FROM python:3.9-slim

RUN mkdir /opt/netscan
COPY . /opt/netscan

RUN cd /opt/netscan && pip3 install --user -r requirements.txt

WORKDIR /opt/netscan

ENTRYPOINT ["/usr/local/bin/python", "./analyzer.py"]