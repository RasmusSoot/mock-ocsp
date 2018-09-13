FROM grahamdumpleton/mod-wsgi-docker:python-3.5

WORKDIR /app

COPY mock_ocspresponder.py /app
COPY monkeypatch.py /app
COPY mock_ocspresponder.wsgi /app
COPY requirements.txt /app
RUN mod_wsgi-docker-build

EXPOSE 80
ENTRYPOINT [ "mod_wsgi-docker-start" ]
CMD [ "mock_ocspresponder.wsgi" ]
