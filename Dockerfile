FROM python:3

ADD pcap_modifier.py .
ADD requirements.txt .

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r ./requirements.txt

ENTRYPOINT ["python", "./pcap_modifier.py"]
