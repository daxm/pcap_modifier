FROM python:3

WORKDIR /app

RUN useradd -ms /bin/bash this_user
USER this_user
RUN chown -R this_user:this_user $WORKDIR

ADD pcap_modifier.py $WORKDIR
ADD infile.pcap $WORKDIR
ADD requirements.txt $WORKDIR

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r $WORKDIR/requirements.txt

ENTRYPOINT ["python", "$WORKDIR/pcap_modifier.py"]
