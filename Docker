FROM python:3.12

ENV APP_HOME /app

WORKDIR $APP_HOME

COPY ./requirements.txt .
RUN pip install -r requirements.txt

COPY . .