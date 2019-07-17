#!/usr/bin/env python3
import logging
import os
import pickle
import subprocess
import sys
from datetime import datetime, timedelta

import boto3
import confuse
import inquirer
from appdirs import user_data_dir, user_log_dir, user_cache_dir
from whoosh import index, analysis, fields, sorting
from whoosh.fields import Schema, TEXT, KEYWORD, ID
from whoosh.qparser import MultifieldParser

app_name = "cloudssh"
app_author = "Haydar Ciftci"

config = confuse.Configuration('CloudSSH')

data_dir = user_data_dir(app_name, app_author)
cache_dir = user_cache_dir(app_name, app_author)
log_dir = user_log_dir(app_name, app_author)

os.makedirs(data_dir, exist_ok=True)
os.makedirs(cache_dir, exist_ok=True)
os.makedirs(log_dir, exist_ok=True)

config_full_path = os.path.join(data_dir, 'config.yml')

if not os.path.exists(config_full_path):
    print("Please create a configuration file at %s.\nSee %s for reference." %
          (
              config_full_path,
              'https://github.com/memoryleak/cloudssh/blob/master/examples/config.yml'
          ))
    sys.exit()

config.set_file(config_full_path)
index_full_dir = os.path.join(cache_dir, config['index']['path'].get())

search_term = None
provider_instances = []
server_instances = []

logging_full_path = os.path.join(log_dir, config['logfile'].get())
logging.basicConfig(filename=logging_full_path,
                    level=config['loglevel'].get())


class ServerInstance:
    def __init__(self, server_name, server_ip_address, server_fields) -> None:
        """
        A basic container for keeping server data.

        :param server_name: Name or label of the server
        :param server_ip_address: The IP address to use
        :param server_fields: Additional fields to be indexed
        """
        self.name = server_name
        self.ip_address = server_ip_address
        self.fields = server_fields


class IndexProcessor:
    def __init__(self, index_config, index_directory_path, index_ttl_file) -> None:
        """
        Processes ServerInstance and adds them to index.

        :param index_directory_path: Path to index directory
        :param index_config: Index configuration object
        """
        self.index_ttl_file = os.path.join(index_ttl_file)
        self.index_directory_path = index_directory_path
        self.instance_index = None
        self.config = index_config

        self.instance_schema = Schema(
            private_ip_address=ID(stored=True, analyzer=analysis.StandardAnalyzer(stoplist=None), unique=True),
            name=TEXT(stored=True, analyzer=analysis.StandardAnalyzer(stoplist=None), sortable=True),
            tags=KEYWORD(stored=True, scorable=True),
            created_at=fields.DATETIME(stored=True, sortable=True)
        )

        self.get_index()

    def should_index(self):
        logging.info("Reading %s index TTL file" % self.index_ttl_file)

        if not os.path.exists(self.index_ttl_file) or not os.path.getsize(self.index_ttl_file) > 0:
            logging.info("TTL file doesn't exist or is empty")
            with open(self.index_ttl_file, 'wb') as ttl_write_handle:
                default_ttl_time = datetime.now() - timedelta(seconds=self.config['ttl'].get() + 1)
                pickle.dump(default_ttl_time, ttl_write_handle, pickle.HIGHEST_PROTOCOL)

        with open(self.index_ttl_file, 'rb') as ttl_read_handle:
            logging.info("Getting delta for TTL check")
            last_indexing_time = pickle.load(ttl_read_handle)
            delta = datetime.now() - last_indexing_time

        should_index = delta.seconds > self.config['ttl'].get()

        logging.info("TTL calculation result: should_index=%s" % should_index)

        if should_index:
            with open(self.index_ttl_file, 'wb') as ttl_write_handle:
                pickle.dump(datetime.now(), ttl_write_handle, pickle.HIGHEST_PROTOCOL)

        return should_index

    def get_index(self):
        """
        Opens or crates the index.

        """
        if not os.path.exists(self.index_directory_path):
            os.mkdir(self.index_directory_path)
            self.instance_index = index.create_in(self.index_directory_path, self.instance_schema)
            logging.info('Created index at %s' % self.index_directory_path)
        else:
            self.instance_index = index.open_dir(self.index_directory_path)
            logging.info('Using index at %s' % self.index_directory_path)

    def update_index(self, instances):
        """
        Adds provided instances to the index.

        :param instances: List of instances to be indexed.
        """
        if not self.should_index():
            logging.info('Index is still valid, TTL not reached')
            return None

        writer = self.instance_index.writer()
        for instance in instances:
            writer.update_document(
                private_ip_address=instance.ip_address,
                name=instance.name,
                tags=str.join(' ', instance.fields),
                created_at=datetime.utcnow()
            )
            logging.info('Indexing %s' % instance.ip_address)
        writer.commit()

    def search(self, query_search_term):
        """
        Searches for provided search term.

        :param query_search_term: The query to be used for the search.
        :return:
        """
        qp = MultifieldParser(["name", "tags"], schema=self.instance_schema)
        q = qp.parse(query_search_term)

        name_field_facet = sorting.FieldFacet("name")
        scores = sorting.ScoreFacet()

        search_results = self.instance_index.searcher().search(q, limit=15, sortedby=[scores, name_field_facet])

        return search_results


class AwsProvider:
    def __init__(self, aws_config) -> None:
        """
        Looks up the running instances in AWS.

        :param aws_config: AWS provider configuration
        """
        self.config = aws_config

    @staticmethod
    def get_name():
        """
        Returns the provider name.

        :return: Name of the provider
        """
        return "aws"

    def lookup(self):
        """
        Looks up the running instances based on the provider configuration provided.
        :return: List of ServerInstances.
        """
        instance_filters = []
        instances = []
        instance_fields = []

        for instance_filter in self.config['filters']:
            instance_filters.append({'Name': instance_filter['Name'].get(), 'Values': instance_filter['Values'].get()})

        ec2client = boto3.client('ec2')
        response = ec2client.describe_instances(Filters=instance_filters)
        logging.info('Received %d reservations' % len(response['Reservations']))

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_name = ''
                for tag in instance['Tags']:
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']

                    instance_fields.append(tag['Value'])

                instances.append(ServerInstance(
                    server_name=instance_name,
                    server_fields=instance_fields,
                    server_ip_address=instance[self.config['address_field'].get()]
                ))

        logging.info('Lookup returned %d instances' % len(instances))
        return instances


for provider in config['providers']:
    if provider == 'aws':
        aws = AwsProvider(config['providers'][provider])
        provider_instances.append(aws)

for provider in provider_instances:
    server_instances += provider.lookup()

processor = IndexProcessor(config['index'], index_full_dir, os.path.join(cache_dir, 'ttl'))
processor.update_index(server_instances)

if len(sys.argv) > 1:
    search_term = str.join(' ', sys.argv[1:])
else:
    try:
        search_term = input("Search: ")
    except TypeError:
        pass

if len(search_term) > 0:
    logging.info("Searching for '%s'..." % search_term)
    results = processor.search(search_term)
    logging.info("Found %s matches..." % len(results))
    prompt_choices = []

    if len(results) > 0:

        for result in results:
            prompt_choices.append(
                "{0} | {1} | {2}".format(
                    result['private_ip_address'].ljust(15),
                    result['name'].ljust(40),
                    result['created_at'].strftime("%H:%M:%S")
                ).strip()
            )

        questions = [
            inquirer.List(
                'ip_address',
                message="Selection ",
                choices=prompt_choices,
            ),
        ]

        answers = inquirer.prompt(questions)
        try:
            ip_address = answers['ip_address'].split(' ')[0]
            subprocess.call('ssh ' + ip_address, shell=True)
        except TypeError:
            pass
