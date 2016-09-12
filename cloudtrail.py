import json, zlib, os, more_itertools
import logging
import requests
import logging.handlers
import json
import boto3


from flask import Flask, request
application = Flask(__name__)

def ensureUtf(s):
    try:
        if type(s) == unicode:
        	return s.encode('utf8', 'ignore')
    except:
        return str(s)

def dict_to_binary(the_dict, doc_id):
	try:
		string=json.dumps(the_dict)
		s = '[{{\"type\":\"add\", \"id\":\"{t}\",\"fields\":{s}}}]'.format(doc_id, string)
		inputbytes = s.encode(encoding='UTF-8')
		return inputbytes
	except Exception as e:
		application.logger.error(str(e.args))

DEFAULT_DOMAIN_NAME = "cloudtrail-1"
DEFAULT_REGION = "us-east-1"
CHUNK_SIZE = 1000 
ENDPOINT_URL="https://cloudtrail.us-east-1.amazonaws.com"

class App_Config:
	app_ok = False
	domain_name = DEFAULT_DOMAIN_NAME
	region = DEFAULT_REGION
	domain = None


g = App_Config()

MAPPING = {
		"aws_region": "awsRegion",
		"error_message": "errorMessage",
		"event_id": "eventID",
		"event_name": "eventName",
		"event_source": "eventSource",
		"event_time": "eventTime",
		"source_ip_address": "sourceIPAddress",
		"user_agent": "userAgent",
		"user_identity_type": "userIdentity.type",
		"user_identity_arn": "userIdentity.arn",
		"user_identity_account_id": "userIdentity.accountId",
		"user_identity_user_name": "userIdentity.userName",
}


@application.route("/")
def home():
	if g.app_ok:
		return "Server operating normally!"
	else:
		return "Unable to initialize application, please see logs.", 503
	

@application.route("/sns/", methods=['POST'])
def sns():
	data = request.get_json(force=True) 
	message_type = data.get('Type', None)

	if message_type == "Notification":
		message = json.loads(data['Message'])
		message_s3_bucket = message['s3Bucket']
		message_s3_object_list = message['s3ObjectKey']
		for message_s3_object in message_s3_object_list:
			application.logger.info('Munching S3 file: s3://%s/%s', message_s3_bucket, message_s3_object)
			upload_s3(message_s3_bucket, message_s3_object)
		return ""
	else:
		application.logger.error("Unknown message type: %s", message_type)
		return "Unknown message type.", 500

def upload_s3(s_bucket, s_key):
	clnt = boto3.client('s3', region_name = DEFAULT_REGION)
	doc_serv = boto3.client('cloudsearchdomain', region_name = DEFAULT_REGION,endpoint_url=ENDPOINT_URL)
	response = clnt.get_object(Bucket=s_bucket,Key=s_key)
	raw_data_gz = response.get('Body').read() 
	raw_data = zlib.decompress(raw_data_gz, 16+zlib.MAX_WBITS) 
	for raw_data_line in raw_data.splitlines(): 
		json_data = json.loads(raw_data_line.decode('utf-8')) 
		for big_chunk in more_itertools.chunked(json_data['Records'], CHUNK_SIZE):
			for json_event in big_chunk:
				doc = {} 		
				doc_id = json_event['eventID'] 
				def search(obj, pattern):
					cur_obj = obj
					for item in pattern.split('.'):
						if not isinstance(cur_obj, dict): 
							return None
						cur_obj = cur_obj.get(item, None)
					return cur_obj
				for cs_name, ct_name in MAPPING.items():
					val = search(json_event, ct_name)
					if val != None:
						application.logger.debug("docId[%s] Adding field CloudSearch ID: %s = %s", doc_id, cs_name, val)
						doc[cs_name] = val
				doc['raw'] = json.dumps(json_event)
				inbytes = dict_to_binary(doc, doc_id)
				try:
					response = doc_serv.upload_documents(contentType='application/json', documents=inbytes)
				except Exception as exception:
					e = exception
					string=json.dumps(doc)
					string = '[{{\"type\":\"add\", \"id\":\"{t}\",\"fields\":{s}}}]'.format(doc_id, string)
					application.logger.error(str(e.args) + "JSON: " + string)
					application.logger.debug('Inserting docId: %s', doc_id)
				application.logger.info('CloudSearch commit ok')

@application.before_first_request
def config_app():
	handler = logging.handlers.WatchedFileHandler('/opt/python/log/cloudtrail.log')
	handler.setLevel(logging.NOTSET)
	handler.setFormatter(logging.Formatter('%(asctime)s %(thread)d %(levelname)s: %(message)s'))
	application.logger.addHandler(handler)
	application.logger.setLevel(logging.INFO)
	g.domain_name = os.environ.get('PARAM1', DEFAULT_DOMAIN_NAME)
	g.region = os.environ.get('PARAM2', DEFAULT_REGION)
	application.logger.info("App info: Region = %s, Search Domain = %s", g.region, g.domain_name)
	clnt1 = boto3.client('cloudsearch', region_name = g.region)
	response = clnt1.describe_domains(DomainNames=[g.domain_name])
	r = json.dumps(response)
	detail = json.loads(r)
	g.domain = detail['DomainStatusList'][0]['DomainName']
	if g.domain == None:
		application.logger.fatal("CloudSearch domain %s not found.", g.domain_name)
		return
	application.logger.debug("Domain = %s", g.domain)
	if g.domain: 
		g.app_ok = True

if __name__ == "__main__":
	application.run('0.0.0.0', 80)