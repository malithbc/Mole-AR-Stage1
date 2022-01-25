import cv2
import numpy as np
import os
import pickle
import base64
from django.core.mail import EmailMessage

def extract_features(image_path):
  image = cv2.imread(image_path, 0)
  dim = (500, 500)
  resize_img = cv2.resize(image, dim, interpolation = cv2.INTER_AREA)
  kaze = cv2.KAZE_create()
  kp, des = kaze.detectAndCompute(resize_img, None)
  return des


def batch_extractor(images_path, image_id, pickled_db_path="features.pck"):
    with open(pickled_db_path, 'rb') as fp:
        data = pickle.load(fp)
    # data = {}

    data[image_id] = extract_features(images_path)
    # print("Extracting features are saved in pickle file")
    # saving all our feature vectors in pickled file
    with open(pickled_db_path, 'wb') as fp:
        pickle.dump(data, fp)

def open_pickle(pickled_db_path="features.pck"):
    with open(pickled_db_path, 'rb') as fp:
        data = pickle.load(fp)

    for d in data:
        print(d)

def find_target_image_id(images_path, pickled_db_path="features.pck"):
    search_image = cv2.imread(images_path, 0)
    dim = (500, 500)
    serImg_resize = cv2.resize(search_image, dim, interpolation = cv2.INTER_AREA)

    kaze = cv2.KAZE_create()
    kp, des = kaze.detectAndCompute(serImg_resize, None)

    with open(pickled_db_path, 'rb') as fp:
        data = pickle.load(fp)

    maxi = 0
    total = 0
    target = None
    for d in data:
        des2 = data.get(d)

        #### Brute Force 
        bf = cv2.BFMatcher()
        matches = bf.knnMatch(des, des2, k=2)
        total=len(matches)
        good = []
        for m, n in matches:
            if m.distance < 0.70*n.distance:
                good.append([m])

        if (maxi<len(good)):
            maxi = len(good)
            target = d
    
    score = (maxi/total)*100

    return [target, score]

def send_mail(data):
    email = EmailMessage(
                subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
    email.send()

def read_file(path):
    with open(path, 'rb') as f:
        contents = base64.b64encode(f.read()).decode('utf-8')
        return contents