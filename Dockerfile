FROM python:3

ARG workdir=/app

RUN mkdir $workdir
RUN mkdir $workdir/pcaps

WORKDIR $workdir

ADD pcap_modifier.py .
ADD infile.pcap .
ADD requirements.txt .

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "pcap_modifier.py"]
