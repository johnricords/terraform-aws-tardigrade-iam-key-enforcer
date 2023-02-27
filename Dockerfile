FROM plus3it/tardigrade-ci:0.24.6

COPY ./src/requirements.txt /lambda/src/requirements.txt

RUN python -m pip install --no-cache-dir \
    -r /lambda/src/requirements.txt
