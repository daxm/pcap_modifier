FROM python:3

ARG workdir=/app
ARG user=this_user
WORKDIR $workdir

RUN useradd -ms /bin/bash $user
USER $user
RUN chown -R $user:$user $workdir

ADD pcap_modifier.py $workdir
ADD infile.pcap $workdir
ADD requirements.txt $workdir

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r $workdir/requirements.txt

ENTRYPOINT ["python", "$workdir/pcap_modifier.py"]
