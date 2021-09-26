FROM python:3.9-slim

# Set Flag Environment Variables
ENV FLAG=DUCTF{d0ubl3_js0n_d0ubl3_URI_r1p_j4s0n5_p4th_w1th_b1g_h4xx}

# Make sure we have the correct directories
RUN mkdir /app

# Copy proxy to /
COPY ./proxy.py / 

# Copy Run Script
COPY ./run.sh /

# Copy challenge files and driver
COPY ./web /app/

# Install Requirements
COPY ./requirements.txt /app/requirements.txt 
RUN pip3 install -r /app/requirements.txt

RUN chmod +x /run.sh
ENV WORKERS=16

ENTRYPOINT ["/bin/bash","/run.sh"]
