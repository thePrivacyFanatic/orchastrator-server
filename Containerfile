FROM library/python

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt --root-user-action ignore

COPY src .

EXPOSE 443

CMD ["python", "./main.py"]
