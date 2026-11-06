FROM mcr.microsoft.com/azure-functions/python:4-python3.10

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true

COPY requirements.txt /home/site/wwwroot/requirements.txt
RUN pip install --no-cache-dir -r /home/site/wwwroot/requirements.txt

COPY function_app.py host.json /home/site/wwwroot/
COPY app /home/site/wwwroot/app
