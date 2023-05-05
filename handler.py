import sys
sys.path.insert(0, 'vendor')

import os
import requests
import random
import json
import base64
from os import environ
import logging
import boto3
from botocore.exceptions import ClientError


def process(message):
    # Prevent self-reply
    if message['sender_type'] != 'bot':
        if message['text'].startswith(PREFIX):
            return None


def send(text, bot_id):
    url = 'https://api.groupme.com/v3/bots/post'

    message = {
        'bot_id': bot_id,
        'text': text,
    }
    r = requests.post(url, json=message)


# Set up logging.
logger = logging.getLogger(__name__)

# Get the model ARN and confidence.
model_arn = environ.get('MODEL_ARN')
min_confidence = int(environ.get('CONFIDENCE', 50))

# Get the boto3 client.
rek_client = boto3.client('rekognition')


def get_source_url(message):
    """
    Given complete message data, extract the URL of the best image to use for a command.
    First choose attached image, then use mentioned person's avatar, then sender's avatar.
    :param message: data of message to extract URL from.
    :return: URL of image to use.
    """
    image_attachments = [attachment for attachment in message["attachments"] if attachment["type"] == "image"]
    if len(image_attachments) > 0:
        # Get sent image
        return image_attachments[0]["url"]


def get_image_base64(url):
    return base64.b64encode(requests.get(url).content)


def receive(event, context):
    message = json.loads(event['body'])

    bot_id = message['bot_id']
    response = process(message)
    if response:
        send(response, bot_id)

    try:
        # Decode the image
        image_bytes = event['image'].encode('utf-8')
        img_b64decoded = base64.b64decode(image_bytes)
        image = {'Bytes': img_b64decoded}

        # Analyze the image.
        response = rek_client.detect_custom_labels(Image=image,
            MinConfidence=min_confidence,
            ProjectVersionArn=model_arn)

        # Get the custom labels
        labels = response['CustomLabels']
        print('Got labels: ' + str(labels))

        send(json.dumps(labels), bot_id)
    except ClientError as err:
        error_message = f'Couldn\'t analyze image. ' + \
            err.response['Error']['Message']
        send(error_message, bot_id)
    except ValueError as val_error:
        lambda_response = {
            'statusCode': 400,
            'body': {
                'Error': 'ValueError',
                'ErrorMessage': format(val_error)
            }
        }
        send('Error function %s: %s' % (context.invoked_function_arn, format(val_error)), bot_id)

    return {
        'statusCode': 200,
        'body': 'ok'
    }
