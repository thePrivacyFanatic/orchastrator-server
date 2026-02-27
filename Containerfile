FROM library/python

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY src .

EXPOSE 443

ENV NAME World

CMD ["python", "./main.py"]