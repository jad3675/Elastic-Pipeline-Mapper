from elasticsearch import Elasticsearch

class ConnectionManager:
    def __init__(self, connection_details):
        self.connection_details = connection_details
        self.es_client = None

    def connect(self):
        """Establish connection to Elasticsearch using provided details."""
        try:
            es_kwargs = {'verify_certs': self.connection_details['verify_ssl']}
            
            if self.connection_details['connection_type'] == "cloud_id":
                cloud_id = self.connection_details['cloud_id']
                if not cloud_id:
                    raise ValueError("Cloud ID is required")
                es_kwargs['cloud_id'] = cloud_id
            else:
                url = self.connection_details['url']
                if not url:
                    raise ValueError("URL is required")
                es_kwargs['hosts'] = [url]
            
            if self.connection_details['auth_type'] == "api_key":
                api_key_str = self.connection_details['api_key']
                if not api_key_str:
                    raise ValueError("API Key is required")
                
                if ':' in api_key_str:
                    api_key_id, api_key_secret = api_key_str.split(':', 1)
                    es_kwargs['api_key'] = (api_key_id, api_key_secret)
                else:
                    es_kwargs['api_key'] = api_key_str
            else:
                username = self.connection_details['username']
                password = self.connection_details['password']
                if not username:
                    raise ValueError("Username is required")
                es_kwargs['basic_auth'] = (username, password)
            
            self.es_client = Elasticsearch(**es_kwargs)
            
            if not self.es_client.ping():
                raise Exception("Failed to connect to Elasticsearch")
            
            return self.es_client
            
        except Exception as e:
            self.es_client = None
            raise e