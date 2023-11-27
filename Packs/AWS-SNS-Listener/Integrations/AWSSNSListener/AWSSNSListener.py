import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from tempfile import NamedTemporaryFile
from traceback import format_exc
from collections import deque
import uvicorn
from secrets import compare_digest
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from pydantic import BaseModel
from CommonServerUserPython import *

sample_events_to_store = deque(maxlen=20)  # type: ignore[var-annotated]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')


class Incident(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    occurred: Optional[str] = None
    raw_json: Optional[Dict] = None


@app.post('/sns')
async def handle_post(
        incident: Incident,
        request: Request,
        credentials: HTTPBasicCredentials = Depends(basic_auth),
        token: APIKey = Depends(token_auth)
):
    demisto.error("Got AWS SNS request")
    header_name = None
    request_headers = dict(request.headers)

    credentials_param = demisto.params().get('credentials')

    # return demisto.createIncidents([incident])


# def handle_external_alert_aws(ac, w, r):
#     aws_request = get_request_body(r)
#     if aws_request.type == "SubscriptionConfirmation":
#         demisto.info("Got AWS SNS subscription confirmation request")
#         req = requests.get(aws_request.subscribe_url)
#         if req.status_code < 200 or req.status_code >= 300:
#             demisto.error(f"Failed handling AWS SNS request, got response: {req.status_code}")
#             write_error(w, ErrAWSSNSSubscriptionRequest, req.text, r)
#             return
#         demisto.info(f"AWS SNS subscription has sent successfully, returned status code: {req.status_code}")
#     elif aws_request.type == "Notification":
#         req = CreateIncidentRequest(incident=Incident())
#         req.incident.name = aws_request.subject
#         req.incident.raw_json_data = aws_request.message
#         req.create_investigation = conf.get_config_bool_or_provided("aws.incidents.api.investigate", True)
#         classifier = conf.get_config_string_or_provided(conf.ExternalServicesClassifierPrefix+domain.AWSDefaultMappingID, "")
#         mapper = conf.get_config_string_or_provided(conf.ExternalServicesMapperPrefix+domain.AWSDefaultMappingID, "")
#         ac.handle_external_alert(w, r, req, classifier, mapper)
#     else:
#         demisto.error("Failed handling AWS SNS request")
#         write_error(w, ErrAWSSNSSubscriptionRequest, "Invalid request type", r)



''' MAIN FUNCTION '''


def main():
    demisto.debug(f'Command being called is {demisto.command()}')
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_policy = None
    aws_access_key_id = params.get('access_key')
    aws_secret_access_key = params.get('secret_key')
    verify_certificate = not params.get('insecure', False)
    # validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
    #                     aws_secret_access_key)
    try:
        try:
            port = int(demisto.params().get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'test-module':
            return "ok"
        # elif demisto.command() == 'fetch-incidents':
        #     fetch_samples()
        elif demisto.command() == 'long-running-execution':
            while True:
                certificate = demisto.params().get('certificate', '')
                private_key = demisto.params().get('key', '')

                certificate_path = ''
                private_key_path = ''
                try:
                    ssl_args = dict()

                    # if certificate and private_key:
                    #     certificate_file = NamedTemporaryFile(delete=False)
                    #     certificate_path = certificate_file.name
                    #     certificate_file.write(bytes(certificate, 'utf-8'))
                    #     certificate_file.close()
                    #     ssl_args['ssl_certfile'] = certificate_path

                    #     private_key_file = NamedTemporaryFile(delete=False)
                    #     private_key_path = private_key_file.name
                    #     private_key_file.write(bytes(private_key, 'utf-8'))
                    #     private_key_file.close()
                    #     ssl_args['ssl_keyfile'] = private_key_path

                    #     demisto.debug('Starting HTTPS Server')
                    # else:
                    #     demisto.debug('Starting HTTP Server')

                    integration_logger = IntegrationLogger()
                    integration_logger.buffering = False
                    log_config = dict(uvicorn.config.LOGGING_CONFIG)
                    log_config['handlers']['default']['stream'] = integration_logger
                    log_config['handlers']['access']['stream'] = integration_logger
                    uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, **ssl_args)
                except Exception as e:
                    demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
                    demisto.updateModuleHealth(f'An error occurred: {str(e)}')
                finally:
                    if certificate_path:
                        os.unlink(certificate_path)
                    if private_key_path:
                        os.unlink(private_key_path)
                    time.sleep(5)
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
