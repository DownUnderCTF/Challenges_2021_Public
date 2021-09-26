FROM python:3.9-slim

# Set Admin Password and Flag Environment Variables
ENV ADMIN_PW=KJDF4wn90sdfjUOIDFndfs2389dsfgj
ENV FLAG=DUCTF{xxX_x55_4_1337_h4x0rz_Xxx}


# Make sure we have the correct directories
RUN mkdir /app

# Copy challenge files and driver
COPY ./challenge/web /app/

# Install Requirements
COPY ./challenge/requirements.txt /app/requirements.txt 
WORKDIR /app
RUN pip3 install -r requirements.txt

# Run create_db script
RUN rm -rf /app/db.sqlite
RUN python3 create_db.py

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", \
    "--access-logfile", "-", \
    "--access-logformat", "%({x-forwarded-for}i)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"", \
    "--forwarded-allow-ips=*", "app:app"]
