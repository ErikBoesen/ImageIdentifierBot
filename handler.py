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


MAX_MESSAGE_LENGTH = 1000


def process(message):
    # Prevent self-reply
    if message['sender_type'] != 'bot':
        if message['text'].startswith(PREFIX):
            return None


def send(text, bot_id):
    url = 'https://api.groupme.com/v3/bots/post'

    if len(text) > MAX_MESSAGE_LENGTH:
        # If text is too long for one message, split it up over several
        for block in [text[i:i + MAX_MESSAGE_LENGTH] for i in range(0, len(text), MAX_MESSAGE_LENGTH)]:
            send(block, bot_id)
            time.sleep(0.3)
        return

    message = {
        'bot_id': bot_id,
        'text': text,
    }
    r = requests.post(url, json=message)


# Set up logging.
logger = logging.getLogger(__name__)

# Get the model ARN and confidence.

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
    source_url = get_source_url(message)
    print('Found source URL: {}'.format(source_url))
    if source_url is not None:
        try:
            # Decode the image
            image_bytes = get_image_base64(source_url)
            img_b64decoded = base64.b64decode(image_bytes)
            image = {'Bytes': img_b64decoded}

            # Analyze the image.
            response = rek_client.detect_labels(
                Image=image,
                MaxLabels=10,
                MinConfidence=40,
            )

            # Get the custom labels
            labels = response['Labels']
            print('Got labels: ' + str(labels))
            message = '\n'.join(
                [
                    '{}: {.3f}'.format(label['Name'], label['Confidence'])
                    for label in labels
                ]
            )

            send(message, bot_id)
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
